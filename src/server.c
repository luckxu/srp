#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <event.h>
#include <fcntl.h>
#include <mysql/mysql.h>
#include <net/if.h>
#include <pthread.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "buffer.h"
#include "common.h"
#include "crypto.h"
#include "network.h"
#include "srp.h"
#ifndef _NODE
#include "dbpool.h"
#endif
#include "connect.h"
#include "list.h"
#include "message.h"

#define MSG_CONN_LOGIN ('a')

typedef struct {
    slist_t list; //挂载链表
    uint64_t id;  // conn连接id
    uint16_t cnt;
    conn_map_t maps[0];
} msg_conn_login_t;

uint32_t keepalive_timer;
static uint64_t id = 1;
static srp_t *server;
static connect_t *new_listen(conn_map_t *map, connect_t *parent);
static int _client_message_proc(connect_t *c);
#ifndef _NODE
static void _conn_login(void *ctx, uint64_t id, void *result);
#endif
#define CONN_NEW(parent) connect_new(id++, (parent))

static int _server_msg_rsapub_push(connect_t *c, message_t *msg) {
    buffer_t *wb;
    RSA *pub = NULL;
    wb = buffer_alloc();
    if (!wb)
        return -1;
    do {
        //使用公共aes密钥解密
        wb->msg.total =
            aes_decrypt(&server->aes_keys.dec_aes, msg->data, msg->total, wb->msg.data, wb->real - sizeof(message_t));
        if (wb->msg.total == 0)
            break;
        wb->msg.total -= msg->padding;
        //解密结果字符串(含结束符)生成公钥rsa_key
        pub = create_rsa_key((char *)wb->msg.data, e_rsa_key_pub);
        if (!pub)
            break;
        //将服务端生成的新AES密钥通过客户端公钥加密后下发至客户端,buffer复用
        wb->msg.total =
            rsa_public_encrypt(pub, c->aes_keys.key, AES_KEY_BYTES, wb->msg.data, wb->real - sizeof(message_t));
        if (wb->msg.total <= 0)
            break;
        wb->msg.magic = MSG_MAGIC;
        wb->msg.id = c->id;
        wb->msg.cmd = MSG_CMD_AESKEY_ASK;
        wb->size = wb->msg.total + sizeof(message_t);
        //已加密处理
        wb->worked = TRUE;
        connect_write(c, wb);
        return 0;
    } while (0);
    buffer_free(wb);
    if (pub)
        RSA_free(pub);
    return -1;
}

static int _string_valid(char *str, int len) {
    assert(len > 0);
    for (int i = 0; i < len; i++) {
        if (!isalnum(str[i]) && str[i] != '\'' && str[i] != '_') {
            log_warn("uuid with invalid characters");
            return -1;
        }
    }
    return 0;
}

static int _server_msg_login_req(connect_t *c, message_t *msg) {
    buffer_t *wb = NULL;
    message_login_req_t *login;
    message_login_ask_t *login_ask;

    wb = buffer_alloc();
    if (!wb)
        return -1;
    do {
        wb->msg.total =
            aes_decrypt(&c->aes_keys.dec_aes, msg->data, msg->total, wb->msg.data, wb->real - sizeof(message_t));
        if (wb->msg.total < sizeof(message_login_req_t))
            break;
        wb->msg.total -= msg->padding;
        login = (message_login_req_t *)wb->msg.data;
        login->uuid[UUID_LEN] = '\0';
        if (_string_valid(login->uuid, strlen(login->uuid))) {
            log_warn("uuid with invalid characters");
            break;
        }
        login->passwd[PASSWD_LEN] = '\0';
        if (_string_valid(login->passwd, strlen(login->passwd))) {
            log_warn("password with invalid characters");
            break;
        }
        if (strlen(server->cfg.passwd) > 0 && strlen(server->cfg.uuid) > 0 &&
            strncmp(login->uuid, server->cfg.uuid, UUID_LEN) == 0 &&
            strncmp(login->passwd, server->cfg.passwd, PASSWD_LEN) == 0) {
            int i = 0;
            c->is_logined = TRUE;
            for (int j = 0; server->cfg.extend && j < server->cfg.extend->cnt; j++) {
                if (!new_listen(server->cfg.extend->maps + j, c))
                    continue;
                i++;
            }
            if (i) {
                login_ask = (message_login_ask_t *)wb->msg.data;
                login_ask->result = 1;
                login_ask->tcp_nodelay = server->cfg.tcp_nodelay;
                wb->msg.magic = MSG_MAGIC;
                wb->msg.id = c->id;
                wb->msg.cmd = MSG_CMD_LOGIN_ASK;
                wb->msg.total = sizeof(message_login_ask_t);
                wb->size = sizeof(message_t) + wb->msg.total;
                //需要加密
                wb->worked = FALSE;
                connect_write(c, wb);
                return 0;
            }
        }
        if (server->dbpool) {
            dbpool_add(server->dbpool, c, c->id, _conn_login,
                       "SELECT a.`id`, b.`id`,b.`listen_addr`,b.`listen_option`+0, "
                       "b.`forward_addr`,b.`forward_option`+0 FROM `proxy_node` a "
                       "LEFT JOIN `v_proxy_forward` b ON a.`id`=b.`node` "
                       "WHERE a.`uuid`='%s' AND a.`password`=PASSWORD('%s%s');",
                       login->uuid, login->uuid, login->passwd);
        }
        buffer_free(wb);
        return 0;
    } while (0);
    buffer_free(wb);
    return -1;
}

static int _server_msg_close_req(connect_t *c, message_t *msg) {
    connect_t *peer = connect_find(msg->id);
    if (peer) {
        peer->close_without_report = TRUE;
        connect_free(peer, TRUE);
    }
    return 0;
}

static int _server_msg_data_req(connect_t *c, message_t *msg) {
    buffer_t *wb;
    connect_t *peer;

    peer = connect_find(msg->id);
    if (!peer) {
        log_debug("connect_find return failed, id:%llu", msg->id);
        return 0;
    }
    wb = buffer_alloc();
    if (!wb)
        return -1;
    wb->msg.total =
        aes_decrypt(&c->aes_keys.dec_aes, msg->data, msg->total, wb->msg.data, wb->real - sizeof(message_t));
    //数据解密失败，返回连接已关闭
    if (wb->msg.total <= 0) {
        log_err("data decrypt failed");
        buffer_free(wb);
        return -1;
    }
    wb->msg.total -= msg->padding;
    //修正数据偏移
    wb->start = sizeof(message_t);
    wb->size = wb->msg.total;
    //转发应用端消息，不加密
    wb->worked = TRUE;
    connect_write(peer, wb);
    return 0;
}

static int _server_message_proc(connect_t *c, message_t *msg) {
    int32_t ret;
    assert(c && !c->parent && msg);
    //检查连接是否已登录，除密钥交换命令外，都需要登录后发送
    if (!c->is_logined && msg->cmd != MSG_CMD_RSAPUB_PUSH_REQ && msg->cmd != MSG_CMD_LOGIN_REQ)
        return -1;
    switch (msg->cmd) {
    case MSG_CMD_RSAPUB_PUSH_REQ:
        ret = _server_msg_rsapub_push(c, msg);
        break;
    case MSG_CMD_LOGIN_REQ:
        ret = _server_msg_login_req(c, msg);
        break;
    case MSG_CMD_CLOSED_RA:
        ret = _server_msg_close_req(c, msg);
        break;
    case MSG_CMD_DATA_REQ:
        ret = _server_msg_data_req(c, msg);
        break;
    case MSG_CMD_KEEPALIVE_REQ:
        ret = 0;
        break;
    default:
        log_warn("unknown msg cmd");
        ret = 0;
        break;
    }

    return ret;
}

static int _args_parse(buffer_t *b, char **args, int argc) {
    char last_b;
    char *t, *o;
    int i, offset;
    assert(b && args && argc);
    memset(args, 0, sizeof(char *) * argc);
    o = (char *)b->msg.data;
    last_b = o[b->start + b->msg.total];
    o[b->msg.total] = '\0';

    t = strchr(o, '\n');
    if (!t)
        return -1;
    *t = '\0';
    offset = t + 1 - o;
    b->msg.total -= offset;
    b->size -= offset;
    b->start += offset;
    if (b->msg.total > 0)
        o[b->start + b->msg.total] = last_b;

    while (isspace(*(--t)))
        *t = '\0';
    while (isspace(*o))
        o++;
    args[0] = o;
    for (i = 1; i < argc; i++) {
        args[i] = strchr(o, ' ');
        if (!args[i])
            break;
        while (isspace(args[i][0])) {
            args[i][0] = '\0';
            args[i]++;
        }
        o = args[i];
    }
    return i;
}

static int _manage_message_proc(connect_t *c) {
    uint64_t id;
    buffer_t *b, *wb;
    connect_t *peer;
    char *args[8];
    int argc;
    struct timeval tv;
    char buf[128];
    b = c->rbuf;
    b->msg.total = b->size - sizeof(message_t);

    do {
        if ((argc = _args_parse(b, args, 8)) <= 0)
            break;
        for (int i = 0; i < argc; i++) {
            log_debug("args[%d] = %s", i, args[i]);
        }
        if (!strcmp(args[0], "map")) {
            //映射命令，将在管理地址上建立的新连接与某一node节点主连接建立映射关系
            //命令格式：map [node连接ID] [转发地址]
            //命令示例：map 1234 tcp://127.0.0.1:22
            if (argc != 3) {
                log_warn("map command: error, usage: map node_connect_id host_addr");
                break;
            }
            id = atoll(args[1]);
            peer = connect_find(id);
            if (!peer || peer->is_listen || !peer->is_connected || !peer->is_logined || peer->parent) {
                log_warn("map command: error, cannot find node connect or node with wrong state");
                break;
            }
            if (e_sock_tcp != socket_addr_format(args[2], &c->forward.addr) || c->forward.addr.sin_port == 0 ||
                c->forward.addr.sin_addr.s_addr == 0) {
                log_warn("map command: error, usage: map node_connect_id host_addr, error: host_addr error");
                break;
            }
            //管理连接的父连接由管理监听连接转移至节点监听连接
            if (!dlist_isempty(&c->parent_list))
                dlist_remove(&c->parent_list);
            dlist_add_after(&peer->child_list, &c->parent_list);
            c->parent = peer;
            //变更为普通连接
            c->is_manage = FALSE;
            wb = buffer_new(MSG_CMD_NEWCONN_ASK, c->id, MSG_MAGIC);
            if (!wb) {
                log_warn("buffer_new failed");
                break;
            }
            sprintf(buf, "success\n");
            log_info("map command: success\n");
            write(c->fd, buf, strlen(buf));
            message_newconn_t *packet = (message_newconn_t *)wb->msg.data;
            memcpy(&packet->forward, &c->forward, sizeof(c->forward));
            wb->size = sizeof(message_t) + wb->msg.total;
            wb->msg.total = sizeof(*packet);
            connect_write(c->parent, wb);
            if (b->msg.total > 0) {
                return _client_message_proc(c);
            }
            return 0;
        }
        if (!strcmp(args[0], "listen")) {
            //监听命令，在指定地址上监听请求并与某一node节点主连接建立主从关系
            //命令格式：listen [node连接ID] [监听地址] [转发地址] [过期时间]
            //命令示例：listen 1234 tcp://127.0.0.1:2222 tcp://127.0.0.1:22 30
            if (argc != 5) {
                log_warn("listen command: error, usage: listen node_connect_id listen_addr forward_addr expire");
                break;
            }
            id = atoll(args[1]);
            peer = connect_find(id);
            if (!peer || peer->is_listen || !peer->is_connected || !peer->is_logined || peer->parent) {
                log_warn("listen command: error, cannot find node or node with incorrect state");
                break;
            }
            conn_map_t map;
            memset(&map, 0, sizeof(map));
            if (e_sock_tcp != socket_addr_format(args[2], &map.listen.addr)) {
                log_warn("listen command: error, unknow listen addr:%s", args[2]);
                break;
            }
            if (e_sock_tcp != socket_addr_format(args[3], &map.forward.addr)) {
                log_warn("listen command: error, unknow forward addr:%s", args[2]);
                break;
            }
            map.expire_at = atoi(args[4]);
            if (map.expire_at) {
                gettimeofday(&tv, NULL);
                map.expire_at += tv.tv_sec;
            }
            peer = new_listen(&map, peer);
            if (peer) {
                sprintf(buf, "success\nid:%lu\nport:%u\n", peer->id, ntohs(map.listen.addr.sin_port));
                write(c->fd, buf, strlen(buf));
                log_info("listen command: success\n");
                return -1;
            }
            //关闭管理连接
            break;
        }
        if (!strcmp(args[0], "kill")) {
            //监听命令，关闭某一连接
            //命令格式：kill [node连接ID]
            //命令示例：kill 1234
            if (argc != 2) {
                log_warn("kill command: error, usage: kill node_connect_id");
                break;
            }
            id = atoll(args[1]);
            peer = connect_find(id);
            if (peer) {
                if (peer->id == server->conn->id || peer->id == server->manage_conn->id)
                    break;
                sprintf(buf, "success\n");
                write(c->fd, buf, strlen(buf));
                connect_free(peer, TRUE);
                log_debug("kill command: success\n");
                return -1;
            } else {
                log_warn("kill command: error, cannot find node or node with incorrect state");
            }
            break;
        }
    } while (0);
    sprintf(buf, "error\n");
    write(c->fd, buf, strlen(buf));
    return -1;
}

static int _client_message_proc(connect_t *c) {
    buffer_t *b;
    assert(c && c->rbuf && c->rbuf->size > sizeof(message_t));
    if (c->is_manage)
        return _manage_message_proc(c);

    // buffer复用
    b = c->rbuf;
    b->msg.total = b->size - sizeof(message_t);
    b->msg.magic = MSG_MAGIC;
    b->msg.cmd = MSG_CMD_DATA_ASK;
    b->msg.id = c->id;
    //转发客户端消息，需要加密
    b->worked = FALSE;
    //有暂存消息，一起发送
    if (c->wbuf_delay) {
        connect_write(c->parent, c->wbuf_delay);
        c->wbuf_delay = NULL;
    }
    connect_write(c->parent, b);
    c->rbuf = NULL;
    return 0;
}

static void _work_msg(int32_t fd, int16_t events, void *ctx) {
    char flag[32];
    int ret, cnt, errno;
    connect_t *c;
    slist_t *l;
    msg_conn_login_t *msg;
    buffer_t *b;
    message_login_ask_t *login_ask;
    while (1) {
        c = NULL;
        ret = read(server->msg_notify[0], &flag, 32);
        if (ret <= 0)
            break;
        for (int i = 0; i < ret; i++) {
            pthread_mutex_lock(&server->mutex);
            l = shead_pop(&server->msg_list);
            pthread_mutex_unlock(&server->mutex);
            assert(l);
            if (flag[i] == MSG_CONN_LOGIN) {
                msg = (msg_conn_login_t *)l;
                c = connect_find(msg->id);
                do {
                    if (!c)
                        break;
                    c->is_logined = TRUE;
                    cnt = 0;
                    for (int j = 0; c && j < msg->cnt; j++) {
                        //新增监听
                        if (!new_listen(msg->maps + j, c)) {
                            if (msg->maps[j].forward_id > 0) {
                                dbpool_add(server->dbpool, NULL, 0, NULL,
                                           "update `proxy_forward` set `server` = NULL,`connect`=NULL,"
                                           "update_at=unix_timestamp() where `forward`=%d;",
                                           msg->maps[j].forward_id);
                            }
                            log_err("listen failed, id:%lld", c->id);
                            continue;
                        }
                        if (server->dbpool && server->server_id > 0 && msg->maps[j].forward_id > 0)
                            dbpool_add(server->dbpool, NULL, 0, NULL,
                                       "update `proxy_forward` set `server` = %d, `connect`=%llu"
                                       "`update_at`=unix_timestamp() where `forward`=%d;",
                                       server->server_id, c->id, msg->maps[j].forward_id);
                        cnt++;
                    }
                    if (cnt) {
                        b = buffer_new(MSG_CMD_LOGIN_ASK, c->id, MSG_MAGIC);
                        if (!b) {
                            connect_free(c, TRUE);
                            break;
                        }
                        login_ask = (message_login_ask_t *)b->msg.data;
                        login_ask->result = 1;
                        login_ask->tcp_nodelay = server->cfg.tcp_nodelay;
                        b->msg.total = sizeof(message_login_ask_t);
                        b->size = sizeof(message_t) + b->msg.total;
                        //需要加密
                        b->worked = FALSE;
                        connect_write(c, b);
                    }
                } while (0);
            }
            free(l);
        }
    }
}

static int _work_keepalive(connect_t *c) {
    struct timeval tv;
    //主连接有登录成功后会设置logined标识
    //主连接初始keepalive_at值为零
    //主连接第一次调用本程序是在连接后五秒
    if (c->keepalive_at == 0) {
        //超时未登录
        if (!c->is_logined) {
            log_warn("client(%llu) timeout", c->id);
            connect_free(c, TRUE);
            return -1;
        }
        //检查通过，修改心跳定时器周期
        tv.tv_sec = server->cfg.keepalive_timer;
        tv.tv_usec = 0;
        event_add(c->read_ev, &tv);
        gettimeofday(&tv, NULL);
        return 0;
    }
    gettimeofday(&tv, NULL);
    //心跳超时或未登录或连接后KEEPALIVE_NODE_INTERVAL秒内未登录则强制
    if (tv.tv_sec - c->keepalive_at > server->cfg.keepalive_timeout || !c->is_logined) {
        log_warn("client(%llu) lost connect", c->id);
        connect_free(c, TRUE);
        return -1;
    }
    //更新数据库应用端信息
    if (server->dbpool && c->node_id > 0)
        dbpool_add(server->dbpool, NULL, 0, NULL,
                   "insert into proxy_traffic_log (`owner_id`, `owner_type`, `read_bytes`, `write_bytes`, `update_at`) "
                   "values (%d, 'node', %u, %u, now());",
                   c->node_id, c->read_bytes, c->write_bytes);
    c->read_bytes = 0;
    c->write_bytes = 0;
    return 0;
}

static void _srp_timer(int32_t fd, int16_t events, void *ctx) {
    uint32_t write_bytes, read_bytes;
    //更新数据库服务器信息
    connect_trans_info(&read_bytes, &write_bytes, TRUE);
    if (server->dbpool && server->server_id > 0)
        dbpool_add(server->dbpool, NULL, 0, NULL,
                   "insert into proxy_traffic_log (`owner_id`, `owner_type`, `read_bytes`, `write_bytes`, `update_at`) "
                   "values (%d, 'server', %u, %u, now());",
                   server->server_id, read_bytes, write_bytes);
}

static void _accept_connect(int32_t fd, int16_t events, void *ctx) {
    struct sockaddr_in addr;
    connect_t *c = NULL, *parent = (connect_t *)ctx;
    buffer_t *b;
    struct timeval tv, *ptv;
    int16_t evs;

    if (events & EV_TIMEOUT) {
        gettimeofday(&tv, NULL);
        if (parent->expire_at && parent->expire_at <= tv.tv_sec)
            connect_free(parent, TRUE);
        return;
    }

    if (!parent->is_manage)
        c = CONN_NEW(parent->parent);
    else {
        c = CONN_NEW(parent);
        c->is_manage = TRUE;
    }
    if (!c)
        return;
    do {
        socklen_t len = sizeof(struct sockaddr_in);
        c->fd = accept(fd, (struct sockaddr *)&addr, &len);
        if (c->fd < 0) {
            log_warn("accpet failed, errno:%d, error:%s", errno, strerror(errno));
            break;
        }
        c->is_connected = TRUE;
        if (set_nonblock(c->fd) < 0) {
            log_warn("set nonblocking failed, client_fd:%d errno:%d error:%s", c->fd, errno, strerror(errno));
            break;
        }
        int flag = 1;
        if (server->cfg.tcp_nodelay)
            setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag));
        //初始化ev_write
        c->write_ev = event_new(server->base, c->fd, EV_WRITE, connect_write_work, c);
        if (!c->write_ev) {
            log_warn("create write event handle failed");
            break;
        }
        c->is_write_ev_add = FALSE;
        evs = EV_READ | EV_PERSIST;
        ptv = NULL;
        //初始化并添加ev_read
        if (!c->parent) {
            //要求在五秒内完成登录，否则会在_work_keepalive中关闭连接
            evs |= EV_TIMEOUT;
            tv.tv_sec = 5;
            tv.tv_usec = 0;
            ptv = &tv;
            if (generate_aes_keypair(&c->aes_keys, AES_KEY_BITS, NULL))
                break;
        } else if (!c->is_manage) {
            //客户端连接， 发送通知消息
            b = buffer_new(MSG_CMD_NEWCONN_ASK, c->id, MSG_MAGIC);
            if (!b)
                break;
            message_newconn_t *packet = (message_newconn_t *)b->msg.data;
            memcpy(&packet->forward, &parent->forward, sizeof(parent->forward));
            b->msg.total = sizeof(*packet);
            b->size = sizeof(message_t) + b->msg.total;
            //延时连接，待接收到数据后再发送连接请求
            if (parent->forward.option & MAP_OPTION_CONNECT_DELAY) {
                if (c->wbuf_delay)
                    connect_write(c->parent, c->wbuf_delay);
                c->wbuf_delay = b;
            } else
                connect_write(c->parent, b);
        }
        c->read_ev = event_new(server->base, c->fd, evs, connect_read_work, c);
        if (!c->read_ev || event_add(c->read_ev, ptv)) {
            log_err("add event to base failed, errno:%d", errno);
            break;
        }
        c->is_read_ev_add = TRUE;
        log_debug("fd:%d, id:%llu, ip:%s, src port:%d", c->fd, c->id, inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        return;
    } while (0);
    connect_free(c, TRUE);
    return;
}

static connect_t *new_listen(conn_map_t *map, connect_t *parent) {
    connect_t *c;
    struct timeval tv, *ptv;
    uint16_t events;
    assert(map);
    c = CONN_NEW(parent);
    if (!c)
        return NULL;
    errno = 0;
    do {
        c->fd = listen_port(&map->listen.addr, !parent);
        if (c->fd < 0)
            break;
        //非异步
        c->is_connected = TRUE;
        events = EV_READ | EV_PERSIST;
        if (map->expire_at) {
            tv.tv_usec = 0;
            tv.tv_sec = 5;
            c->expire_at = map->expire_at;
            ptv = &tv;
            events |= EV_TIMEOUT;
        } else {
            ptv = NULL;
        }
        c->read_ev = event_new(server->base, c->fd, events, _accept_connect, c);
        if (!c->read_ev || event_add(c->read_ev, ptv)) {
            log_err("add event to base failed, errno:%d", errno);
            break;
        }
        c->is_read_ev_add = TRUE;
        c->is_write_ev_add = FALSE;
        c->is_listen = TRUE;
        memcpy(&c->forward, &map->forward, sizeof(map->forward));
        return c;
    } while (0);
    connect_free(c, TRUE);
    return NULL;
}

static void _srps_fetch_server_id(void *ctx, uint64_t id, void *result) {
    MYSQL_RES *res = (MYSQL_RES *)result;
    MYSQL_ROW row;
    unsigned int rows;
    assert(result);
    rows = mysql_num_rows(res);
    if (rows < 1)
        return;
    while ((row = mysql_fetch_row(res))) {
        if (row[0]) {
            server->server_id = atoi(row[0]);
            break;
        }
    }
}

static void _register_server() {
    int fd;
    DIR *dirs;
    struct dirent *entry;
    //取第一张网卡的IP地址标识该代理服务器
    char ip[PASSWD_LEN + 1];
    struct ifreq ifr;

    memset(ip, 0, sizeof(ip));
    while (1) {
        dirs = opendir("/sys/class/net/");
        if (dirs) {
            fd = -1;
            while (NULL != (entry = readdir(dirs))) {
                if (memcmp(entry->d_name, "lo", strlen(entry->d_name)) && entry->d_name[0] != '.') {
                    fd = socket(AF_INET, SOCK_DGRAM, 0);
                    if (fd < 0)
                        break;
                    memset(&ifr, 0, sizeof(ifr));
                    strncpy(ifr.ifr_name, entry->d_name, 16);
                    ifr.ifr_name[15] = 0;
                    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0)
                        break;
                    snprintf(ip, 16, "%s", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
                    break;
                }
            }
            if (fd >= 0)
                close(fd);
            closedir(dirs);
        }
        if (ip[0])
            break;
        sleep(1);
        log_warn("get ip address failed");
    }
    //更新服务器信息
    if (server->dbpool) {
        dbpool_add(server->dbpool, NULL, 0, NULL,
                   "insert into proxy_server (`ip`, `listen_port`, `manage_port`, `update_at`) "
                   "values ('%s', '%s', %d, %d, now()) on duplicate key update "
                   "`ip`=values(`ip`), `listen_port`=values(`listen_port`), "
                   "`manage_port`=values(`manage_port`),`update_at`=now();",
                   ip, ntohs(server->cfg.listen_addr.sin_port), ntohs(server->cfg.manage_addr.sin_port));
        dbpool_add(server->dbpool, NULL, 0, _srps_fetch_server_id, "select `id` from proxy_server where `ip`='%s';",
                   ip);
    }
}

static int _connect_close_before(connect_t *c) {
    if (!c->parent && c->node_id > 0) {
        dbpool_add(server->dbpool, NULL, 0, NULL,
                   "update proxy_forward set "
                   "connect=null, server=null where node=%d;",
                   c->node_id);
    }
    return 0;
}

void srps_new(srp_config_t *config) {
    conn_map_t map;
    assert(config);
    config->connect_cbs.keepalive = _work_keepalive;
    config->connect_cbs.server_message_proc = _server_message_proc;
    config->connect_cbs.client_message_proc = _client_message_proc;
    config->connect_cbs.close_before = _connect_close_before;
    config->msg_fn = _work_msg;
    config->timer_fn = _srp_timer;
    keepalive_timer = config->keepalive_timer;
    server = srp_new(config);
    if (!server)
        exit(-1);

    id = rand();
    //主连接只使用了map.listen.addr值
    memset(&map, 0, sizeof(map));
    memcpy(&map.listen.addr, &config->listen_addr, sizeof(config->listen_addr));
    do {
        server->conn = new_listen(&map, NULL);
        sleep(1);
    } while (!server->conn);
    //管理连接
    if (config->manage_addr.sin_addr.s_addr != 0) {
        memcpy(&map.listen.addr, &config->manage_addr, sizeof(config->manage_addr));
        do {
            server->manage_conn = new_listen(&map, NULL);
            sleep(1);
        } while (!server->manage_conn);
        server->manage_conn->is_manage = TRUE;
    }
    _register_server();
}

#ifndef _NODE
static void _conn_login(void *ctx, uint64_t id, void *result) {
    unsigned int rows;
    MYSQL_RES *res = (MYSQL_RES *)result;
    MYSQL_ROW row;
    msg_conn_login_t *msg;
    char flag[] = {MSG_CONN_LOGIN};
    int i;
    e_sock_t st;
    connect_t *c = (connect_t *)ctx;
    assert(ctx && result);

    // id不一致，一般发生在关闭connect后内存被复用时
    if (c->id != id)
        return;

    do {
        rows = mysql_num_rows(res);
        if (rows < 1)
            return;
        msg = (msg_conn_login_t *)calloc(1, sizeof(msg_conn_login_t) + rows * sizeof(conn_map_t));
        if (!msg)
            return;
        msg->id = c->id;
        msg->cnt = rows;
        i = 0;
        while ((row = mysql_fetch_row(res))) {
            memset(msg->maps + i, 0, sizeof(conn_map_t));
            if (!c->node_id && row[0])
                c->node_id = atoi(row[0]);
            msg->maps[i].forward_id = (row[1]) ? atoi(row[1]) : -1;
            if (row[2]) {
                st = socket_addr_format(row[2], &msg->maps[i].listen.addr);
                if (e_sock_tcp != st) {
                    log_warn("node listen address error, only support tcp address, value:%s", row[2]);
                }
            } else
                continue;
            msg->maps[i].listen.option = (row[3]) ? atoi(row[3]) : 0;
            if (row[4]) {
                st = socket_addr_format(row[4], &msg->maps[i].forward.addr);
                if (e_sock_tcp != st && e_sock_udp != st) {
                    log_warn("node forward address error, only support tcp and udp address, value:%s, ret:%d", row[4]);
                }
            } else
                continue;
            msg->maps[i].forward.option = (row[5]) ? atoi(row[5]) : 0;
            i++;
        }
    } while (0);
    pthread_mutex_lock(&server->mutex);
    if (write(server->msg_notify[1], flag, 1) == 1) {
        shead_add_tail(&server->msg_list, &msg->list);
    }
    pthread_mutex_unlock(&server->mutex);
}
#endif
