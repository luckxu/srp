#include "srp.h"
#include <event.h>
#include <string.h>
#include <unistd.h>
#include "access_control.h"
#include "buffer.h"
#include "common.h"
#include "connect.h"
#include "crypto.h"
#include "message.h"
#include "network.h"

#define MAIN_CONN_ID 0xffffffffffff //主连接ID

static srp_t *server;
static uint32_t try_interval = 0; //主连接断链或登录失败后重试间隔，每失败一次加1秒
static uint64_t try_at = 0;       //主连接重连时间
static connect_t *new_connect(struct sockaddr_in *addr, connect_t *parent, uint64_t id, uint32_t option);
uint32_t keepalive_timer;

static int _server_message_data_req(connect_t *c, message_t *msg) {
    buffer_t *wb;
    connect_t *peer;
    wb = buffer_alloc();
    if (!wb)
        return -1;
    do {
        wb->msg.total =
            aes_decrypt(&c->aes_keys.dec_aes, msg->data, msg->total, wb->msg.data, wb->real - sizeof(message_t));
        //数据解密失败，返回连接已关闭
        if (wb->msg.total == 0) {
            log_err("data decrypt failed");
            break;
        }
        wb->msg.total -= msg->padding;
        peer = connect_find(msg->id);
        if (!peer) {
            buffer_free(wb);
            return 0;
        }
        //修正数据偏移
        wb->start = sizeof(message_t);
        wb->size = wb->msg.total;
        //转发数据，不需要加密
        wb->worked = TRUE;
        connect_write(peer, wb);
        return 0;
    } while (0);
    buffer_free(wb);
    return -1;
}

static int _server_message_newconn(connect_t *c, message_t *msg) {
    connect_t *peer;
    message_newconn_t *newconn;
    buffer_t *wb;
    wb = buffer_alloc();
    if (!wb)
        return -1;
    do {
        wb->msg.total =
            aes_decrypt(&c->aes_keys.dec_aes, msg->data, msg->total, wb->msg.data, wb->real - sizeof(message_t));
        if (wb->msg.total == 0)
            break;
        wb->msg.total -= msg->padding;
        if (wb->msg.total < sizeof(*newconn))
            break;
        //当查找不到连接句柄时新建连接
        peer = connect_find(msg->id);
        if (peer)
            connect_free(peer, FALSE);
        newconn = (message_newconn_t *)wb->msg.data;
        peer = new_connect(&newconn->forward.addr, server->conn, msg->id, newconn->forward.option);
        //连接失败，返回连接已关闭请求
        if (!peer) {
            wb->msg.total = 0;
            wb->msg.magic = MSG_MAGIC;
            wb->msg.cmd = MSG_CMD_CLOSED_RA;
            wb->msg.id = msg->id;
            //需要加密
            wb->worked = FALSE;
            wb->size = wb->msg.total + sizeof(message_t);
            connect_write(c, wb);
            return 0;
        }
        buffer_free(wb);
        return 0;
    } while (0);
    buffer_free(wb);
    return -1;
}

static int _server_message_aeskey_ask(connect_t *c, message_t *msg) {
    buffer_t *wb;
    message_login_req_t *ask;
    wb = buffer_alloc();
    if (!wb)
        return -1;
    do {
        //使用RSA私钥解密
        wb->msg.total = rsa_private_decrypt(server->rsa_keys.pri_rsa, msg->data, msg->total, wb->msg.data,
                                            wb->real - sizeof(message_t));
        if (wb->msg.total <= 0) {
            log_err("data decrypt failed!");
            break;
        }
        if (wb->msg.total < AES_KEY_BYTES) {
            log_err("aes key length error!");
            break;
        }
        if (generate_aes_keypair(&c->aes_keys, AES_KEY_BITS, wb->msg.data) < 0) {
            log_err("create aes_keys failed");
            break;
        }
        ask = (message_login_req_t *)wb->msg.data;
        strncpy((char *)ask->uuid, server->cfg.uuid, UUID_LEN + 1);
        strncpy((char *)ask->passwd, server->cfg.passwd, PASSWD_LEN + 1);
        wb->msg.total = sizeof(*ask);
        wb->msg.magic = MSG_MAGIC;
        wb->msg.cmd = MSG_CMD_LOGIN_REQ;
        //需要加密
        wb->worked = FALSE;
        wb->size = wb->msg.total + sizeof(message_t);
        connect_write(c, wb);
        return 0;
    } while (0);
    buffer_free(wb);
    return -1;
}

static int _server_message_login_ask(connect_t *c, message_t *msg) {
    buffer_t *wb;
    message_login_ask_t *ask;
    int flag;
    wb = buffer_alloc();
    if (!wb)
        return -1;
    do {
        wb->msg.total =
            aes_decrypt(&c->aes_keys.dec_aes, msg->data, msg->total, wb->msg.data, wb->real - sizeof(message_t));
        if (wb->msg.total == 0)
            break;
        wb->msg.total -= msg->padding;
        ask = (message_login_ask_t *)wb->msg.data;
        server->cfg.tcp_nodelay = ask->tcp_nodelay;
        flag = ask->tcp_nodelay;
        if (ask->tcp_nodelay)
            setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag));
        try_interval = 0;
        buffer_free(wb);
        c->is_logined = TRUE;
        return 0;
    } while (0);
    buffer_free(wb);
    return -1;
}

static int _server_message_close(connect_t *c, message_t *msg) {
    connect_t *peer;
    peer = connect_find(msg->id);
    if (peer) {
        peer->close_without_report = TRUE;
        connect_free(peer, TRUE);
    }
    return 0;
}

static int _server_message_proc(connect_t *c, message_t *msg) {
    assert(c && !c->parent && msg);
    int ret;
    switch (msg->cmd) {
    case MSG_CMD_DATA_ASK:
        ret = _server_message_data_req(c, msg);
        break;
    case MSG_CMD_NEWCONN_ASK:
        ret = _server_message_newconn(c, msg);
        break;
    case MSG_CMD_AESKEY_ASK:
        ret = _server_message_aeskey_ask(c, msg);
        break;
    case MSG_CMD_LOGIN_ASK:
        ret = _server_message_login_ask(c, msg);
        break;
    case MSG_CMD_CLOSED_RA:
        ret = _server_message_close(c, msg);
        break;
    default:
        log_err("unknow msg cmd");
        ret = 0;
        break;
    }
    return ret;
}

static int _client_message_proc(connect_t *c) {
    buffer_t *b;
    assert(c && c->rbuf && c->rbuf->size > sizeof(message_t));
    b = c->rbuf;
    b->msg.total = b->size - sizeof(message_t);
    b->msg.magic = MSG_MAGIC;
    b->msg.cmd = MSG_CMD_DATA_REQ;
    b->msg.id = c->id;
    //转发客户端消息，需要加密
    b->worked = FALSE;
    connect_write(c->parent, b);
    //指针清空，等下次读socket时重新分配
    c->rbuf = NULL;
    return 0;
}

static inline void _update_reconnect_info() {
    struct timeval tv;
    uint64_t usec;
    gettimeofday(&tv, NULL);
    usec = try_interval * (server->cfg.timer_tv.tv_sec * 1000000 + server->cfg.timer_tv.tv_usec);
    try_at = tv.tv_sec * 1000000 + tv.tv_usec + usec;
    if (usec < 5000000)
        try_interval++;
}

static int _conn_close_after(connect_t *c) {
    //主连接关闭时清除主连接指针
    if (c->id == MAIN_CONN_ID) {
        server->conn = NULL;
        _update_reconnect_info();
    }
    return 0;
}

static int _work_keepalive(connect_t *c) {
    buffer_t *b;
    b = buffer_new(MSG_CMD_KEEPALIVE_REQ, c->id, MSG_MAGIC);
    connect_write(c, b);
    return 0;
}

static void _srp_timer(int32_t fd, int16_t events, void *ctx) {
    struct timeval tv;
    srp_t *srv = (srp_t *)ctx;
    uint64_t now;
    //主连接处于断开状态，重连
    if (!srv->conn) {
        gettimeofday(&tv, NULL);
        now = tv.tv_sec * 1000000 + tv.tv_usec;
        if (try_at <= now)
            srv->conn = new_connect(&server->cfg.server, NULL, MAIN_CONN_ID, 0);
    }
}

static connect_t *new_connect(struct sockaddr_in *addr, connect_t *parent, uint64_t id, uint32_t option) {
    connect_t *c;
    buffer_t *b;
    // 客户端异步连接
    int async = !!parent && !(option & MAP_OPTION_CONNECT_UDP);
    struct timeval tv = {0, 0};
    //有禁止规则且规则匹配时拒绝
    //或有允许规则且规则未匹配时拒绝
    if (parent &&
        ((server->cfg.deny_roles && !ac_check(addr, !!(option & MAP_OPTION_CONNECT_UDP), server->cfg.deny_roles)) ||
         (server->cfg.allow_roles && ac_check(addr, !!(option & MAP_OPTION_CONNECT_UDP), server->cfg.allow_roles)))) {
        log_info("access control return failed, ip:%s, port:%d, option:%d", inet_ntoa(addr->sin_addr),
                 ntohs(addr->sin_port), option);
        return NULL;
    }
    c = connect_new(id, parent);
    if (!c)
        return NULL;
    do {
        c->fd = connect_port(addr, async, option);
        if (c->fd <= 0)
            break;

        // 同步连接将状态设置为"已连接"
        c->is_connected = !async || (option & MAP_OPTION_CONNECT_UDP);
        int flag = 1;
        setsockopt(c->fd, SOL_SOCKET, SO_REUSEADDR, (char *)&flag, sizeof(flag));
        if (server->cfg.tcp_nodelay)
            setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag));
        if (!parent) {
            tv.tv_sec = server->cfg.keepalive_timer;
            c->read_ev = event_new(server->base, c->fd, EV_TIMEOUT | EV_READ | EV_PERSIST, connect_read_work, c);
            if (!c->read_ev || event_add(c->read_ev, &tv)) {
                log_err("add event to base failed, errno:%d", errno, evutil_gai_strerror(errno));
                break;
            }
            gettimeofday(&tv, NULL);
            c->keepalive_at = tv.tv_sec;
            //初始连接，交换RSA公钥先
            generate_aes_keypair(&c->aes_keys, AES_KEY_BITS, (uint8_t *)server->cfg.aes_key);
            b = buffer_new(MSG_CMD_RSAPUB_PUSH_REQ, 0, MSG_MAGIC);
            if (b) {
                b->msg.total = strlen((char *)server->rsa_keys.pub_str) + 1;
                memcpy(b->msg.data, server->rsa_keys.pub_str, b->msg.total);
                b->size = b->msg.total + sizeof(message_t);
                b->worked = FALSE;
                connect_write(c, b);
            }
        } else {
            c->read_ev = event_new(server->base, c->fd, EV_READ | EV_PERSIST, connect_read_work, c);
            if (!c->read_ev || event_add(c->read_ev, NULL)) {
                log_err("add event to base failed, errno:%d", errno, evutil_gai_strerror(errno));
                break;
            }
        }
        c->is_read_ev_add = TRUE;
        memcpy(&c->forward.addr, addr, sizeof(*addr));
        c->forward.option = option;
        c->write_ev = event_new(server->base, c->fd, EV_WRITE, connect_write_work, c);
        if (!c->write_ev) {
            log_err("create write event handle failed");
            break;
        }
        //异常连接，在connect_write_work中完成链接或连接超时
        if (!c->is_connected) {
            tv.tv_sec = 5;
            tv.tv_usec = 0;
            event_add(c->write_ev, &tv);
            c->is_write_ev_add = TRUE;
        } else
            c->is_write_ev_add = FALSE;
        log_debug("create new connection, fd:%d, ip:%s, dst port:%d", c->fd, inet_ntoa(addr->sin_addr),
                  ntohs(addr->sin_port));
        return c;
    } while (0);
    //创建主连接失败，计算重试时间
    if (!parent) {
        _update_reconnect_info();
    }
    connect_free(c, TRUE);
    return NULL;
}

static int _connect_close_before(connect_t *c) {
    if (!c->parent)
        server->conn = NULL;
    return 0;
}

void srpn_new(srp_config_t *config) {
    assert(config);
    config->connect_cbs.keepalive = _work_keepalive;
    config->connect_cbs.server_message_proc = _server_message_proc;
    config->connect_cbs.client_message_proc = _client_message_proc;
    config->connect_cbs.close_after = _conn_close_after;
    config->connect_cbs.close_before = _connect_close_before;
    config->msg_fn = NULL;
    config->timer_fn = _srp_timer;
    keepalive_timer = config->keepalive_timer;
    server = srp_new(config);
    if (!server)
        exit(-10000);
}
