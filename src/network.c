#include <event2/dns.h>
#include <event2/event.h>
#include <event2/util.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include "network.h"
#include "common.h"

e_sock_t socket_addr_format(const char *host, struct sockaddr_in *addr) {
    char tmp[128];
    char *ps;
    int offset;
    e_sock_t ret = e_sock_err;
    if (!strncmp(host, "tcp://", 6)) {
        ret = e_sock_tcp;
        offset = 6;
    } else if (!strncmp(host, "udp://", 6)) {
        ret = e_sock_udp;
        offset = 6;
    } else {
        log_warn("address(%s) error", host);
        return ret;
    }
    memcpy(tmp, host + offset, strlen(host) - offset + 1);
    ps = strchr(tmp, ':');
    if (ps)
        *ps++ = '\0';
    memset(addr, 0, sizeof(*addr));
    addr->sin_family = AF_INET;
    if (!inet_pton(AF_INET, tmp, &addr->sin_addr) || addr->sin_addr.s_addr == 0xffffffff) {
        char ip[16];
        get_ip_by_name(tmp, ip);
        if (!inet_pton(AF_INET, ip, &addr->sin_addr) || addr->sin_addr.s_addr == 0xffffffff) {
            log_warn("address(%s) error", host);
            return e_sock_err;
        }
    }
    if (ps) {
        int port = atoi(ps);
        if (port < 0 || port > 65535) {
            log_warn("port(%d) error", host);
            return e_sock_err;
        }
        addr->sin_port = htons(port);
    }
    return ret;
}

void close_socket(int32_t fd) {
    int ret = evutil_closesocket(fd);
    while (ret != 0) {
        if (errno != EINTR || errno == EBADF)
            break;
        ret = evutil_closesocket(fd);
    }
}

int32_t set_nonblock(int32_t fd) {
    int flags;

    flags = fcntl(fd, F_GETFL);
    if (flags < 0)
        return flags;
    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) < 0)
        return -1;

    return 0;
}

int32_t listen_port(struct sockaddr_in *addr, int reuseaddr) {
    int32_t fd;
    socklen_t size;
    int32_t flag = 1;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        log_err("open server socket failed, errno:%d error:%s", errno, strerror(errno));
        return -1;
    }

    if (set_nonblock(fd) < 0) {
        log_err("cannot set nonblocking, errno:%d error:%s", errno, strerror(errno));
        close(fd);
        return -1;
    }
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&flag, sizeof(flag));
    flag = 1;
    if (reuseaddr)
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (char *)&flag, sizeof(flag));


    if (bind(fd, (const struct sockaddr *)addr, sizeof(*addr)) != 0) {
        log_err("bind failed, ip:%s port:%d errno:%d error:%s", inet_ntoa(addr->sin_addr), ntohs(addr->sin_port), errno,
                strerror(errno));
        close_socket(fd);
        return -1;
    }

    if (listen(fd, 1024) != 0) {
        log_err("listen failed, ip:%s, port:%d errno:%d error:%s", inet_ntoa(addr->sin_addr), ntohs(addr->sin_port),
                errno, strerror(errno));
        close_socket(fd);
        return -1;
    }
    if (!addr->sin_port) {
        size = sizeof(struct sockaddr);
        getsockname(fd, (struct sockaddr *)addr, &size);
    }

    log_debug("listen success:fd:%d, ip:%s, port:%d", fd, inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
    return fd;
}

int32_t connect_port(struct sockaddr_in *addr, int async, int option) {
    int32_t fd;
    assert((async && !(option & MAP_OPTION_CONNECT_UDP)) || !async);
    if (!(option & MAP_OPTION_CONNECT_UDP)) {
        fd = socket(AF_INET, SOCK_STREAM, 0);
    } else
        fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (-1 == fd) {
        log_err("create socket failed, ip:%s, port:%d, errno %d, error:%s", inet_ntoa(addr->sin_addr),
                ntohs(addr->sin_port), errno, strerror(errno));
        return -1;
    }

    if (async && set_nonblock(fd) < 0) {
        log_err("cannot set nonblocking, errno:%d error:%s", errno, strerror(errno));
        close(fd);
        return -1;
    }

    if (-1 == connect(fd, (struct sockaddr *)addr, sizeof(struct sockaddr))) {
        //异步连接
        if (async && (errno == EINPROGRESS || errno == EWOULDBLOCK)) {
            return fd;
        }
        log_info("connect failed, ip:%s, port:%d, errno %d, error:%s", inet_ntoa(addr->sin_addr), ntohs(addr->sin_port),
                 errno, strerror(errno));
        close(fd);
        return -1;
    }
    //同步连接，非阻塞
    if (set_nonblock(fd) < 0) {
        log_err("cannot set nonblock flag, errno:%d error:%s", errno, strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
};

static struct event_base *base;
static void _get_host_ip_callback(int errcode, struct evutil_addrinfo *addr, void *ip) {
    char buf[128];
    if (!errcode && addr) {
        struct evutil_addrinfo *ai;
        //遍历链表
        for (ai = addr; ai; ai = ai->ai_next) {
            const char *s = NULL;
            if (ai->ai_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)ai->ai_addr;
                s = evutil_inet_ntop(AF_INET, &sin->sin_addr, buf, 128);
                strncpy((char *)ip, s, strlen(s) + 1);
                log_debug("evdns_getaddressinfo return ip:%s", s);
                break;
            } else
                log_warn("evdns_getaddressinfo failed");
        }
        evutil_freeaddrinfo(addr);
    }
    event_base_loopexit(base, NULL);
}

void get_ip_by_name(const char *host, char *ip) {
    assert(host && ip);
    base = event_base_new();
    struct evdns_base *dnsbase = evdns_base_new(base, 0);
    evdns_base_resolv_conf_parse(dnsbase, DNS_OPTION_HOSTSFILE, NULL);
    //使用公共DNS服务器
    evdns_base_nameserver_ip_add(dnsbase, "8.8.8.8");
    evdns_base_nameserver_ip_add(dnsbase, "114.114.114.114");
    struct evutil_addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_flags = EVUTIL_AI_CANONNAME;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    struct evdns_getaddrinfo_request *req = evdns_getaddrinfo(dnsbase, host, NULL, &hints, _get_host_ip_callback, ip);
    if (req)
        event_base_dispatch(base);
    evdns_base_free(dnsbase, 0);
    event_base_free(base);
}
