#include <ctype.h>
#include <getopt.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>
#include "buffer.h"
#include "common.h"
#include "config.h"
#include "network.h"
#include "srp.h"

// worker 进程数量
static int worker_num = 0;
static void child_func(srp_config_t *config) {
    srps_new(config);
    while (1) {
        sleep(1);
    }
}

#define CFG_STEP_SYSTEM 0
#define CFG_STEP_NODE 1
static unsigned int map_option_format(char *option) {
    char *next, *tmp;
    uint32_t inv = 0;
    while (option) {
        next = strchr(option, ',');
        tmp = next;
        if (next) {
            *next++ = '\0';
            while ((--tmp) >= option && isspace(*tmp))
                *tmp = '\0';
        }
        while (*option && isspace(*option))
            option++;
        if (!strcmp(option, MAP_OPTION_CONNECT_DELAY_NAME)) {
            inv |= MAP_OPTION_CONNECT_DELAY;
        }
        option = next;
    }
    return inv;
}

static int config_proc(char *file, srp_config_t *cfg) {
    FILE *fd;
    char line[1024];
    char *key, *value;
    conf_ret_t ret;
    conn_map_t *map;
    conn_extend_t *extend;
    int map_cnt;
    // map有效标识，bit0为listen有效，bit1为forward有效
    int map_valid = 0;
    e_sock_t st;
    int step = CFG_STEP_NODE, intval;
    struct sockaddr_in addr;

    map_cnt = 32;
    extend = (conn_extend_t *)calloc(1, sizeof(*extend) + sizeof(conn_map_t) * map_cnt);
    if (!extend) {
        log_err("calloc failed");
        cfg->extend = NULL;
        return -1;
    }
    cfg->extend = extend;
    fd = fopen(file, "r");
    if (!fd) {
        log_err("open file(%s) failed", file);
        return -1;
    }
    while (fgets(line, 1024, fd)) {
        ret = get_string(line, &key, &value);
        switch (ret) {
        case e_error:
            continue;
        case e_tag:
            if (!strcmp(key, "system")) {
                step = CFG_STEP_SYSTEM;
            } else {
                //当前map填充完毕，加1
                if (map_valid == 3)
                    extend->cnt++;
                //必要时扩容
                if (extend->cnt >= map_cnt) {
                    map_cnt <<= 1;
                    extend = (conn_extend_t *)realloc(extend, sizeof(*extend) + sizeof(conn_map_t) * map_cnt);
                    if (!extend) {
                        log_err("realloc failed");
                        cfg->extend = NULL;
                        return -1;
                    }
                    cfg->extend = extend;
                }
                //指向待填充map
                map = extend->maps + extend->cnt;
                memset(map, 0, sizeof(*map));
                map_valid = 0;
                step = CFG_STEP_NODE;
            }
            log_debug("tag:%s", key);
            continue;
        case e_cfg:
            log_debug("key:%s, value:%s", key, value);
            break;
        case e_none:
            continue;
        default:
            log_warn("unknow return value(%d)", ret);
            continue;
        }
        if (step == CFG_STEP_SYSTEM) {
            if (!strcmp(key, "password")) {
                strncpy(cfg->passwd, value, PASSWD_LEN + 1);
            } else if (!strcmp(key, "uuid")) {
                strncpy(cfg->uuid, value, UUID_LEN + 1);
            } else if (!strcmp(key, "listen")) {
                if (e_sock_tcp != socket_addr_format(value, &addr)) {
                    log_err("system.listen address(%s) error", value);
                    return -1;
                }
                memcpy(&cfg->listen_addr, &addr, sizeof(addr));
            } else if (!strcmp(key, "manage_listen")) {
                if (e_sock_tcp != socket_addr_format(value, &addr)) {
                    log_err("system.listen address(%s) error", value);
                    return -1;
                }
                memcpy(&cfg->manage_addr, &addr, sizeof(addr));
            } else if (!strcmp(key, "worker")) {
                intval = atoi(value);
                if (intval > 0)
                    worker_num = intval;
            } else if (!strcmp(key, "aes_key")) {
                memcpy(cfg->aes_key, value, strlen(value) > AES_KEY_BYTES ? AES_KEY_BYTES : strlen(value));
            } else if (!strcmp(key, "connect_slot_cnt")) {
                cfg->connect_slot_cnt = atoi(value);
                if (cfg->connect_slot_cnt < 128) {
                    log_warn("system.connect_slot_cnt error, must big than or equal to 128");
                    cfg->connect_slot_cnt = 128;
                }
            } else if (!strcmp(key, "timer")) {
                cfg->timer_tv.tv_sec = atoi(value);
                if (cfg->timer_tv.tv_sec < 1) {
                    log_err("system.timer error, must big than or equal to 1");
                    return -1;
                }
            } else if (!strcmp(key, "keepalive_timer")) {
                intval = atoi(value);
                if (cfg->keepalive_timer <= 0) {
                    log_err("system.keepalive_timer error, mast bigger than 0");
                    continue;
                }
                cfg->keepalive_timer = intval;
            } else if (!strcmp(key, "keepalive_timeout")) {
                cfg->keepalive_timeout = atoi(value);
            } else if (!strcmp(key, "db_host")) {
                strncpy(cfg->dbpool_cfg.host, value, sizeof(cfg->dbpool_cfg.host) - 1);
            } else if (!strcmp(key, "db_dbname")) {
                strncpy(cfg->dbpool_cfg.db, value, sizeof(cfg->dbpool_cfg.db) - 1);
            } else if (!strcmp(key, "db_user")) {
                strncpy(cfg->dbpool_cfg.user, value, sizeof(cfg->dbpool_cfg.user) - 1);
            } else if (!strcmp(key, "db_password")) {
                strncpy(cfg->dbpool_cfg.password, value, sizeof(cfg->dbpool_cfg.password) - 1);
            } else if (!strcmp(key, "tcp_nodelay") && memcmp(value, "on", 2) == 0) {
                cfg->tcp_nodelay = TRUE;
            }
        } else if (step == CFG_STEP_NODE) {
            if (!strcmp(key, "listen_addr")) {
                st = socket_addr_format(value, &map->listen.addr);
                if (e_sock_tcp != st) {
                    log_err("node.listen_addr address(%s) error, only support tcp socket.", value);
                    return -1;
                }
                map_valid |= 1;
            } else if (!strcmp(key, "listen_option")) {
                map->listen.option = map_option_format(value);
            } else if (!strcmp(key, "forward_addr")) {
                st = socket_addr_format(value, &map->forward.addr);
                if (e_sock_udp == st) {
                    map->forward.option |= MAP_OPTION_CONNECT_UDP;
                } else if (e_sock_tcp != st) {
                    log_err("node.forward_addr address(%s) error", value);
                    return -1;
                }
                map_valid |= 2;
            } else if (!strcmp(key, "forward_option")) {
                map->forward.option |= map_option_format(value);
            }
        }
    }
    //当前map填充完毕，加1
    if (map_valid == 3)
        extend->cnt++;
    return 0;
}

int main(int argc, char *argv[]) {
    int d = FALSE;
    int opt, pid, status;
    errno = 0;
    srp_config_t config;
    char *config_file = NULL;
    sys_init();
    memset(&config, 0, sizeof(config));
    socket_addr_format(DEFAULT_LISTEN_ADDR, &config.listen_addr);
    config.connect_slot_cnt = 4096;
    config.buffer_chunk_size = BUFFER_CHUNK_SIZE;
    config.buffer_hold_max_bytes = 0x4000000;
    config.timer_tv.tv_sec = 60;
    config.timer_tv.tv_usec = 0;
    config.keepalive_timer = KEEPALIVE_TIMER;
    config.keepalive_timeout = KEEPALIVE_TIMEOUT;
    config.dbpool_cfg.port = 3306;
    memcpy(config.aes_key, PROXY_AES_KEY,
           strlen(PROXY_AES_KEY) > AES_KEY_BYTES ? AES_KEY_BYTES : strlen(PROXY_AES_KEY));
    set_log_level(log_level_info);
    while ((opt = getopt(argc, argv, "dc:l:")) != -1) {
        switch (opt) {
        case 'd':
            d = TRUE;
            break;
        case 'c':
            config_file = optarg;
            break;
        case 'l':
            set_log_level(atoi(optarg));
            break;
        default:
            break;
        }
    }
    if (d)
        set_log_level(log_level_error);
    if (!config_file)
        config_file = "/etc/srp/srps.conf";
    if (config_proc(config_file, &config) < 0) {
        log_err("config process failed");
        exit(-1);
    }

    if (config.keepalive_timer >= config.keepalive_timeout / 3)
        config.keepalive_timer = config.keepalive_timeout / 3;

    process_rename("srp: server master process", argv);
    if (!d) {
        child_func(&config);
        while (1) {
            sleep(1);
        }
    }
    if (daemon(0, 1) < 0)
        log_err("create daemon failed, errstr:%s", strerror(errno));
    long ncpu = sysconf(_SC_NPROCESSORS_CONF);
    if (worker_num > 0 && worker_num < ncpu)
        ncpu = worker_num;
    while (ncpu) {
        pid = fork();
        if (0 > pid) {
            log_err("fork error, errstr:%s", strerror(errno));
            sleep(1);
            continue;
        }
        if (0 == pid) {
            process_rename("srp: server worker process", argv);
            child_func(&config);
            exit(-1);
        }
        ncpu--;
    }
    pid = wait(&status);
    if (-1 == pid)
        log_err("wait() reture:%d, errstr:%s", pid, strerror(errno));

    while (1) {
        pid = fork();
        if (0 > pid) {
            log_err("fork error, errstr:%s", strerror(errno));
            sleep(1);
            continue;
        }
        if (0 == pid) {
            process_rename("srp: server worker process", argv);
            child_func(&config);
            exit(-1);
        }
        pid = wait(&status);
        if (-1 == pid) {
            log_err("wait() reture:%d, errstr:%s", pid, strerror(errno));
        }
        sleep(1);
    }
}
