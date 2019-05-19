#include <event.h>
#include <string.h>
#include <unistd.h>
#include "connect.h"
#include "common.h"
#include "crypto.h"
#include "list.h"
#include "message.h"
#include "network.h"

typedef struct {
    slist_t free;         //分配的client一般不会释放，放在free链表暂存并复用
    uint32_t all_conn;    //已分配的连接总数
    uint32_t free_conn;   //已分配但处于空闲状态的连接总数
    uint16_t slot_cnt;    // slot数量
    uint32_t read_bytes;  //上行数据量
    uint32_t write_bytes; //下行数据量
    slist_t slots[0];     // slot槽位
} connect_pool_t;

static connect_cb_t callbacks;
static connect_pool_t *pool;
extern uint32_t tick;
extern uint32_t keepalive_timer;

connect_t *connect_find(uint64_t id) {
    slist_t *slot;
    connect_t *c;
    slot = pool->slots[id % pool->slot_cnt].next;
    while (slot) {
        c = struct_entry(slot, connect_t, slot);
        if (c->id == id)
            return c;
        slot = slot->next;
    }
    return NULL;
}

void _connect_remove(connect_t *c) {
    slist_t *slot;
    assert(c);
    slot = &pool->slots[c->id % pool->slot_cnt];
    while (slot) {
        if (slot->next == &c->slot) {
            slot->next = slot->next->next;
            return;
        }
        slot = slot->next;
    }
}

void _connect_insert(connect_t *c) {
    assert(c);
    slist_t *slot;
    slot = &pool->slots[c->id % pool->slot_cnt];
    slist_push(slot, &c->slot);
}

void connect_free(connect_t *c, int32_t force) {
    buffer_t *b;
    dlist_t *l;
    connect_t *child;
    connect_t *p;
    assert(c);
    p = c->parent;
    if (!c->is_valid) {
        log_info("invalid connections");
        return;
    }
    if (!force && !shead_isempty(&c->wbuf_list)) {
        c->is_wait_close = TRUE;
        return;
    }
    log_debug("close, fd:%d, id:%llu", c->fd, c->id);
    if (c->fd > 0 && callbacks.close_before) {
        callbacks.close_before(c);
    }
    if (c->read_ev) {
        if (c->is_read_ev_add) {
            event_del(c->read_ev);
        }
        event_free(c->read_ev);
        //防止再次调用event_add
        c->is_read_ev_add = TRUE;
        c->read_ev = NULL;
    }
    if (c->write_ev) {
        if (c->is_write_ev_add) {
            event_del(c->write_ev);
        }
        event_free(c->write_ev);
        //防止再次调用event_add
        c->is_write_ev_add = TRUE;
        c->write_ev = NULL;
    }
    if (!dlist_isempty(&c->parent_list))
        dlist_remove(&c->parent_list);
    //节点，关闭所有子连接且无需上报
    while ((l = dlist_pop(&c->child_list))) {
        child = struct_entry(l, connect_t, parent_list);
        child->close_without_report = TRUE;
        connect_free(child, TRUE);
    }
    if (!dlist_isempty(&c->wait_read_list))
        dlist_remove(&c->wait_read_list);
    //释放未写入的数据
    if (c->rbuf)
        buffer_free(c->rbuf);
    if (c->wbuf_delay)
        buffer_free(c->wbuf_delay);
    //清除存在mplist上暂存的数据
    while ((b = buffer_pop(&c->wbuf_list)) != NULL) {
        if (!c->is_listen && p) {
            p->cli_wbuf_bytes -= b->size;
        }
        buffer_free(b);
    }
    //父连接待写入缓存低于阈值时启用父连接的可读事件监听
    if (p && !p->is_read_ev_add && p->read_ev && p->cli_wbuf_bytes < CONN_ENABLE_READ_LOW_TH) {
        event_add(p->read_ev, NULL);
        p->is_read_ev_add = TRUE;
    }
    if (c->fd > 0) {
        if (p && !c->is_listen && !c->is_manage && !c->close_without_report) {
            b = buffer_new(MSG_CMD_CLOSED_RA, c->id, MSG_MAGIC);
            if (b)
                connect_write(p, b);
        }
        //从slot中删除该连接
        close_socket(c->fd);
        if (!c->is_listen && callbacks.close_after)
            callbacks.close_after(c);
    }
    _connect_remove(c);
    memset(c, 0, sizeof(connect_t));
    pool->free_conn++;
    slist_push(&pool->free, &c->slot);
}

connect_t *connect_new(uint64_t id, connect_t *parent) {
    connect_t *c = NULL;
    slist_t *slot;
    slot = slist_pop(&pool->free);
    if (slot) {
        c = struct_entry(slot, connect_t, slot);
        pool->free_conn--;
    } else {
        c = malloc(sizeof(connect_t));
        pool->all_conn++;
    }
    if (!c)
        return NULL;
    memset(c, 0, sizeof(*c));
    c->id = id;
    //父节点不为空则挂载到父节点上
    dlist_init(&c->child_list);
    if (parent) {
        dlist_add_after(&parent->child_list, &c->parent_list);
        c->parent = parent;
    } else {
        dlist_init(&c->parent_list);
    }

    dlist_init(&c->wait_read_list);
    _connect_insert(c);
    c->is_valid = TRUE;
    return c;
}

/**
 * @brief 向客户端写入数据
 *
 * @param client 客户端句柄
 * @param buffer 待写入数据缓存
 * @return int32_t 返回值小于零表示错误，需要关闭连接；返回0表示数据已写入缓存；返回1表示未写完，待一次可写事件继续写入
 *
 * 调用write_buffer后,buffer将被占用并在write_buffer及相关流程中释放，调用者不能再使用buffer
 */
static e_ret_t _connect_write_buffer(connect_t *c, buffer_t *b) {
    int size;
    uint8_t *data;
    assert(c && b && b->size > 0);
    data = (uint8_t *)&b->msg;
    size = write(c->fd, data + b->start, b->size);
    if (size < 0) {
        log_debug("write to client(%d) failed, errno:%d error:%s", c->fd, errno, strerror(errno));
        if (errno == EINTR || errno == EAGAIN) {
            buffer_push(&c->wbuf_list, b, FALSE);
            return e_ret_tryagain;
        } else
            return e_ret_error; // Some other socket error occurred, exit
    }

    log_debug("write, fd:%d, id:%llu, write %d bytes", c->fd, c->id, size);
    if (c->parent) {
        c->parent->cli_wbuf_bytes -= size;
    } else {
        c->node_wbuf_bytes -= size;
        c->write_bytes += size;
        pool->write_bytes += size;
    }
    if (size != b->size) {
        b->start += size;
        b->size -= size;
        buffer_push(&c->wbuf_list, b, FALSE);
        return e_ret_tryagain;
    }
    buffer_free(b);
    return e_ret_success;
}

/**
 * @brief 向客户端写入数据
 *
 * @param client 客户端句柄
 * @param buffer 待写入数据缓存
 *
 * 调用write_buffer后,buffer将被占用并在write_buffer及相关流程中释放，调用者不能再使用buffer
 */
void connect_write(connect_t *c, buffer_t *b) {
    int32_t ret = e_ret_success;
    connect_t *child, *p;
    dlist_t *l;
    buffer_t *tb;
    int8_t merged = FALSE;
    p = c->parent;
    errno = 0;
    if (!c) {
        log_warn("write buffer, c == NULL");
        buffer_free(b);
        return;
    }
    if (b) {
        if (!b->worked && b->msg.total) {
            b->msg.padding = AES_BLOCK_SIZE - (b->msg.total % AES_BLOCK_SIZE);
            b->msg.padding &= (AES_BLOCK_SIZE - 1);
            b->msg.total =
                aes_encrypt(&c->aes_keys.enc_aes, b->msg.data, b->msg.total, b->msg.data, b->real - sizeof(message_t));
            if (b->msg.total <= 0) {
                log_err("data encrypt failed, fd:%d", c->fd);
                buffer_free(b);
                return;
            }
            b->size = b->msg.total + sizeof(message_t);
            b->worked = TRUE;
        }
        if (c->wbuf_list.tail) {
            tb = struct_entry(c->wbuf_list.tail, buffer_t, list);
            if (tb->size + tb->start + b->size < tb->real) {
                memcpy((char *)&tb->msg + tb->start + tb->size, (char *)&b->msg + b->start, b->size);
                tb->size += b->size;
                merged = TRUE;
            }
        }
        if (p) {
            p->cli_wbuf_bytes += b->size;
        } else {
            c->node_wbuf_bytes += b->size;
        }
        if (!merged)
            buffer_push(&c->wbuf_list, b, TRUE);
        else
            buffer_free(b);
    }

    //已添加读事件监听或未连接时，由可写事件完成数据写入
    if (c->is_write_ev_add || !c->is_connected)
        return;

    while (1) {
        b = buffer_pop(&c->wbuf_list);
        if (!b)
            break;
        ret = _connect_write_buffer(c, b);
        if (ret != e_ret_success)
            break;
    }

    //节点待写入缓存量低于CONN_ENABLE_READ_LOW_TH时，启用所有被禁用的客户端连接读事件监控
    if (!p && c->cli_wbuf_bytes < CONN_ENABLE_READ_LOW_TH) {
        while ((l = dlist_pop(&c->wait_read_list))) {
            child = struct_entry(l, connect_t, wait_read_list);
            event_add(child->read_ev, NULL);
            child->is_read_ev_add = TRUE;
        }
    }
    //客户端待写入缓存总量低于CONN_ENABLE_READ_LOW_TH时启用节点读事件监控
    else if (p && !p->is_read_ev_add && p->node_wbuf_bytes < CONN_ENABLE_READ_LOW_TH) {
        event_add(p->read_ev, NULL);
        p->is_read_ev_add = TRUE;
    }
    if ((c->is_wait_close && shead_isempty(&c->wbuf_list)) || ret == e_ret_error) {
        connect_free(c, TRUE);
    } else if (ret == e_ret_tryagain) {
        event_add(c->write_ev, NULL);
        c->is_write_ev_add = TRUE;
    }
}

void connect_write_work(int32_t fd, int16_t events, void *ctx) {
    connect_t *c = (connect_t *)ctx;
    if (!c->is_valid)
        return;
    do {
        if (events & EV_WRITE) {
            //异步连接
            if (!c->is_connected) {
                int err;
                socklen_t len = sizeof(err);
                getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &len);
                if (err) {
                    log_info("connect failed, fd:%d, ip:%s, src port:%d", c->fd, inet_ntoa(c->forward.addr.sin_addr),
                             ntohs(c->forward.addr.sin_port));
                    break;
                }
                c->is_connected = TRUE;
            }
            c->is_write_ev_add = FALSE;
            connect_write(c, NULL);
            return;
        }
        // EV_TIMEOUT
        else {
            log_info("connect failed, fd:%d, ip:%s, src port:%d", c->fd, inet_ntoa(c->forward.addr.sin_addr),
                     ntohs(c->forward.addr.sin_port));
            break;
        }
    } while (0);
    connect_free(c, TRUE);
}

static int _server_message_proc(connect_t *c) {
    buffer_t *b;
    int32_t ret;
    message_t *msg;
    assert(c && c->rbuf && !c->parent);
    b = c->rbuf;
    do {
        ret = -1;
        msg = (message_t *)((uint8_t *)&b->msg + b->start);
        //未接收完头部数据，等待下次处理
        if (b->size < sizeof(message_t)) {
            ret = 0;
            break;
        }
        //未接收完完整数据包，等待下次处理
        if (b->size < msg->total + sizeof(message_t)) {
            if (msg->total > BUFFER_CHUNK_SIZE - sizeof(buffer_t)) {
                log_err("message total valued error, total:%d", msg->total);
                break;
            }
            //剩余空间容不下一个完整包，移动数据
            else if (b->real - b->start < msg->total + sizeof(message_t)) {
                memmove(&b->msg, msg, b->size);
                b->start = 0;
            }
            ret = 0;
            break;
        }
        if (msg->magic != MSG_MAGIC) {
            log_warn("magic error");
            break;
        }
        ret = callbacks.server_message_proc(c, msg);
        if (!ret) {
            b->start += msg->total + sizeof(message_t);
            b->size -= msg->total + sizeof(message_t);
        } else {
            log_info("server_message_proc return error, cmd:%d", msg->cmd);
            break;
        }
    } while (1);

    if (b->size == 0)
        b->start = 0;

    return ret;
}

void connect_read_work(int32_t cfd, int16_t events, void *ctx) {
    connect_t *c = (connect_t *)ctx, *p;
    int32_t size;
    buffer_t *b = NULL;
    uint8_t *data;
    assert(c);
    p = c->parent;
    errno = 0;

    //主连接keepalive_timer时长的可读超时事件或上次主连接心跳与当前时间差大于keepalive_timer
    //服务端调用心跳检查函数，节点端调用心跳发送函数
    if (events & EV_TIMEOUT || (c->is_logined && c->keepalive_at + keepalive_timer < tick)) {
        callbacks.keepalive(ctx);
        c->keepalive_at = tick;
        return;
    }

    //非可读事件时退出
    if (!(events & EV_READ))
        return;

    //连接可能在消息处理函数中被关闭
    while (c->is_valid) {
        // NODE读流控依赖其子连接待写入数据量
        if (!p && c->cli_wbuf_bytes > CONN_DISABLE_READ_HIGH_TH) {
            event_del(c->read_ev);
            c->is_read_ev_add = FALSE;
            return;
        }
        // CLI读流程依赖其父连接待写入数据量
        if (p && p->node_wbuf_bytes > CONN_DISABLE_READ_HIGH_TH) {
            event_del(c->read_ev);
            c->is_read_ev_add = FALSE;
            //转移至待添加读事件链表
            dlist_add_after(&p->wait_read_list, &c->wait_read_list);
            return;
        }
        if (!c->rbuf) {
            c->rbuf = buffer_alloc();
            if (!c->rbuf)
                return;
            //客户端消息需要重新打包，留出prx_msg_t空间待后续填充
            if (p)
                c->rbuf->size = sizeof(message_t);
        }
        b = c->rbuf;
        data = (uint8_t *)&b->msg + b->start + b->size;
        size = b->real - b->size - b->start;
        if (size > 0) {
            size = read(cfd, data, size);
            if (size <= 0)
                goto read_error;
            log_debug("read, fd:%d, id:%llu, read %d bytes", c->fd, c->id, size);
            b->size += size;
            if (!p) {
                c->read_bytes += size;
                pool->read_bytes += size;
            }
        }
        //未读取到完整数据头部
        if (b->size < sizeof(message_t))
            continue;
        //节点发送至服务端的消息
        if (!p && _server_message_proc(c))
            goto out;
        //客户端发送至服务端的消息
        else if (p && callbacks.client_message_proc(c))
            goto out;
    }
    return;
read_error:
    if (c->is_valid && size < 0 && (errno == EAGAIN || errno == EINTR))
        return;
//其它错误则关闭连接
out:
    if (!c->is_valid) {
        log_warn("connect closed with invalid flag, fd:%d, id:%llu", cfd, c->id);
        return;
    }
    if (size < 0 && errno)
        log_debug("read failed, cfd:%d, fd:%d, id:%llu, ret:%d, errno:%d error:%s", cfd, c->fd, c->id, size, errno,
                  strerror(errno));
    connect_free(c, TRUE);
}

void connect_pool_init(uint32_t slot_cnt, connect_cb_t *cbs) {
    assert(slot_cnt && cbs && !pool);
    int32_t size = sizeof(*pool) + sizeof(slist_t) * slot_cnt;
    pool = calloc(1, size);
    if (!pool) {
        log_err("calloc failed!");
        exit(-1);
    }
    pool->slot_cnt = slot_cnt;
    memcpy(&callbacks, cbs, sizeof(*cbs));
}

void connect_trans_info(uint32_t *read_bytes, uint32_t *write_bytes, int32_t clear) {
    *read_bytes = pool->read_bytes;
    *write_bytes = pool->write_bytes;
    if (clear) {
        pool->read_bytes = pool->write_bytes = 0;
    }
}
