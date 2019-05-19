#ifndef __SRP_CONNECT_H__
#define __SRP_CONNECT_H__
#include <event.h>
#include "buffer.h"
#include "common.h"

#define CONN_DISABLE_READ_HIGH_TH 0x20000 //写缓存总数高于此值时禁用读事件
#define CONN_ENABLE_READ_LOW_TH 0x10000   //写缓存总数低于此值时启用读事件

// tcp连接控制块
typedef struct _prx_conn_t {
    slist_t slot;                 //空闲或slot表
    dlist_t parent_list;          //父链表
    dlist_t child_list;           //子链表
    dlist_t wait_read_list;       //被取消读事件的子孙节点
    struct _prx_conn_t *parent;   //父节点
    uint64_t id;                  //连接ID
    struct event *read_ev;        //读事件
    struct event *write_ev;       //写事件
    buffer_t *rbuf;               //接收缓存
    buffer_t *wbuf_delay;         //暂缓发送数据
    shead_t wbuf_list;            //发送缓存链表
    aes_keys_t aes_keys;          // AES加密信息，每个连接都会随机生成AES加密密钥
    int32_t fd;                   // socket
    uint32_t is_listen : 1;       //是否是监听连接
    uint32_t is_valid : 1;        //有效标识
    uint32_t is_logined : 1;      //连接已登录
    uint32_t is_wait_close : 1;   //写完后关闭连接
    uint32_t is_write_ev_add : 1; //可写事件已添加
    uint32_t is_read_ev_add : 1;  //可读事件已添加
    uint32_t is_connected : 1;    //已正确连接
    uint32_t is_manage : 1;       //是否为管理连接
#ifndef _NODE
    int32_t node_id; //数据库的节点ID
#endif
    uint32_t close_without_report : 1; //关闭且无需汇报
    int32_t cli_wbuf_bytes;            //节点关联的客户端待写入缓存总数，限速
    int32_t node_wbuf_bytes;           //节点待写入缓存总数，限速
    uint32_t keepalive_at;             //最后一次心跳时间
    uint32_t read_bytes;               //上行数据量
    uint32_t write_bytes;              //下行数据量
    uint32_t expire_at;                //过期时间，0为不过期
    conn_addr_t forward;
} connect_t;

//消息回调
typedef int (*connect_cb)(connect_t *);
//消息处理回调
typedef int (*message_cb)(connect_t *, message_t *msg);

typedef struct {
    connect_cb msg_client;          //客户端消息处理函数
    message_cb server_message_proc; //服务端消息处理函数
    connect_cb client_message_proc; //客户端消息处理函数
    connect_cb close_before;        //关闭前触发函数
    connect_cb close_after;         //关闭后触发函数，部分资源已释放，请谨慎操作
    connect_cb keepalive; //心跳处理函数, 只有节点连接才会定时keepalive_timer秒触发此函数
} connect_cb_t;

connect_t *connect_find(uint64_t id);
void connect_free(connect_t *c, int32_t force);
connect_t *connect_new(uint64_t id, connect_t *parent);
void connect_write(connect_t *c, buffer_t *b);
void connect_write_work(int32_t fd, int16_t events, void *ctx);
void connect_read_work(int32_t fd, int16_t events, void *ctx);
void connect_pool_init(uint32_t slot_cnt, connect_cb_t *cbs);
void connect_trans_info(uint32_t *read_bytes, uint32_t *write_bytes, int32_t clear);
#endif