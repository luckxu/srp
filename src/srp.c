#include <event.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include "srp.h"
#include "buffer.h"
#include "common.h"
#include "crypto.h"
#include "list.h"
#include "message.h"
#include "network.h"
#ifndef _NODE
#include "dbpool.h"
#endif

uint32_t tick = 0;
static struct event *tick_ev;

static void _tick_timer(int32_t fd, int16_t events, void *ctx) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    tick = tv.tv_sec;
}

static void _srp_timer(int32_t fd, int16_t events, void *ctx) {
    srp_t *srv = (srp_t *)ctx;
    if (srv && srv->cfg.timer_fn)
        srv->cfg.timer_fn(fd, events, ctx);
}

static void *_srp_loop(void *arg) {
    srp_t *srv = (srp_t *)arg;
    event_base_loop(srv->base, 0);
    event_base_free(srv->base);
    srv->cfg.exit_fn(srv);
    exit(-1);
}

srp_t *srp_new(srp_config_t *cfg) {
    srp_t *srv;
    int ret;
    struct timeval tv;

    srv = (srp_t *)calloc(1, sizeof(srp_t));
    if (!srv) {
        log_err("calloc failed");
        return NULL;
    }
    //初始化随机数种子
    gettimeofday(&tv, NULL);
    srand(tv.tv_usec);

    do {
        memcpy(&srv->cfg, cfg, sizeof(*cfg));
        //初始化连接池
        connect_pool_init(cfg->connect_slot_cnt, &cfg->connect_cbs);
        //初始化缓存池
        buffer_pool_init(cfg->buffer_hold_max_bytes, cfg->buffer_chunk_size);

        // event_enable_debug_logging(EVENT_DBG_ALL);
        //随机生成新的RSA密钥
        ret = generate_rsa_keypair(&srv->rsa_keys, RSA_KEY_BITS);
        if (ret) {
            log_err("create rsa keypair failed!");
            break;
        }
        //使用默认aes密钥
        ret = generate_aes_keypair(&srv->aes_keys, AES_KEY_BITS, (uint8_t *)srv->cfg.aes_key);
        if (ret) {
            log_err("create aes keypair failed!");
            break;
        }

        srv->base = event_init();
        if (!srv->base) {
            log_err("Could not initialize libevent!");
            break;
        }

        tv.tv_sec = 1;
        tv.tv_usec = 0;
        //定时器相关
        tick_ev = event_new(srv->base, -1, EV_READ | EV_PERSIST, _tick_timer, srv);
        if (!tick_ev) {
            log_err("create tick event handle failed");
            break;
        }
        event_add(tick_ev, &tv);

        //定时器相关
        srv->timer_ev = event_new(srv->base, -1, EV_READ | EV_PERSIST, _srp_timer, srv);
        if (!srv->timer_ev) {
            log_err("create tiver event handler failed");
            break;
        }
        event_add(srv->timer_ev, &cfg->timer_tv);

#ifndef _NODE
        if (strlen(cfg->dbpool_cfg.host) >= 7 && cfg->dbpool_cfg.user[0] != '\0' &&
            cfg->dbpool_cfg.password[0] != '\0' && cfg->dbpool_cfg.db[0] != '\0' && cfg->dbpool_cfg.port > 0)
            srv->dbpool = dbpool_create(&cfg->dbpool_cfg);
#endif
        if (cfg->msg_fn) {
            shead_init(&srv->msg_list);
            pipe(srv->msg_notify);
            set_nonblock(srv->msg_notify[0]);
            srv->msg_ev = event_new(srv->base, srv->msg_notify[0], EV_READ | EV_PERSIST, cfg->msg_fn, NULL);
            if (!srv->msg_ev || event_add(srv->msg_ev, NULL) == -1) {
                log_err("add event to base failed, errno:%d", errno);
                break;
            }
        }
        signal(SIGPIPE, SIG_IGN);
        pthread_mutex_init(&srv->mutex, NULL);
        pthread_create(&srv->event_thread, NULL, _srp_loop, srv);
        pthread_detach(srv->event_thread);
        return srv;
    } while (0);

    if (srv) {
        log_err("create prx_srv failed");
        free(srv);
    }
    return NULL;
}
