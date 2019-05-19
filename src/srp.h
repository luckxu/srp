#ifndef __SRP_PROXY_H__
#define __SRP_PROXY_H__
#include <event.h>
#include <pthread.h>
#include "connect.h"
#include "dbpool.h"
#ifdef _NODE
#include "access_control.h"
#endif

typedef struct _srp_t srp_t;

// server/proxy公共配置参数
typedef struct {
    uint16_t connect_slot_cnt;  //连接槽位数
    connect_cb_t connect_cbs;   //连接相关的回调
    event_callback_fn msg_fn;   //消息处理函数，libevent线程与其它线程通信时使用
    event_callback_fn timer_fn; //定时器处理函数，主线程定时器，定时时长为timer_tv
    void *(*exit_fn)(srp_t *);  // event退出处理函数
    struct timeval
        timer_tv; //服务器定时器时长(s);
                  //server定时器中完成流量统计信息上报、更新server.update_at时间等工作,默认30s；node定时器完成节点连接断链重连
    uint16_t
        keepalive_timer; //服务端节点心跳超时检查定时器时长(s)，最长60秒；在该定时器中还会完成节点流量上报、更新node.update_at等工作。默认60s
    uint16_t
        keepalive_timeout; //服务端节点心跳超时检时长(s)，服务端超过此时长未收到节点上报的心跳则强制关闭连接。此值不得低于keepalive_timer，默认120s
    uint16_t buffer_chunk_size;     //每chunk大小
    uint32_t buffer_hold_max_bytes; //内存池最大保持内存(不释放)大小
    uint32_t tcp_nodelay;           // TCP_NODELAY标志
    db_config_t dbpool_cfg;         // mysql线程池配置函数
#ifdef _NODE
    struct sockaddr_in server; //服务器地址
#else
    struct sockaddr_in listen_addr; //服务器监听地址
    struct sockaddr_in manage_addr; //服务器端管理地址
#endif
    char passwd[PASSWD_LEN + 1]; //默认passwd
    char uuid[UUID_LEN + 1];     //默认uuid
    char aes_key[AES_KEY_BYTES]; //公共aes加密密钥
#ifdef _NODE
    ac_roles_t *deny_roles;  //连接黑名单
    ac_roles_t *allow_roles; //连接白名单, 先检查黑名单，再检查白名单
#endif
    conn_extend_t *extend;
} srp_config_t;

// server/proxy公共结构
typedef struct _srp_t {
    srp_config_t cfg;
    pthread_t event_thread; // libevent事件循环线程
    pthread_mutex_t mutex;  //线程间通信互斥锁
    struct event_base *base;
    struct event *timer_ev; //定时器
    uint32_t test;
    connect_t *conn; //主连接或监听句柄
#ifndef _NODE
    connect_t *manage_conn; //服务端管理端口监听连接
    int32_t server_id; //数据库存储的代理服务器记录ID，为-1表示无数据库或代理服务器注册失败
#endif
    dbpool_t *dbpool;     //数据库连接池句柄
    rsa_keys_t rsa_keys;  // rsa密钥
    aes_keys_t aes_keys;  // aes密钥
    struct event *msg_ev; //多线程通信event句柄
    int msg_notify[2];    //多线程通信管道
    shead_t msg_list;     //多线程消息列表
} srp_t;

srp_t *srp_new(srp_config_t *cfg);
void srps_new(srp_config_t *config);
void srpn_new(srp_config_t *config);
#endif