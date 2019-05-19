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
#ifdef _NODE
#include "access_control.h"
#endif

int child_func(srp_config_t *config) {
    srpn_new(config);
    while (1) {
        sleep(1);
    }
}

static int config_proc(char *file, srp_config_t *cfg) {
    FILE *fd;
    char line[1024];
    char *key, *value, *tmp;
    conf_ret_t ret;
    int intval;
    int i = 0;
    struct sockaddr_in addr;

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
        if (!strcmp(key, "password")) {
            for (i = 0; i < strlen(value) && i < PASSWD_LEN; i++) {
                if (!isalnum(value[i])) {
                    log_err("system.passwd with invalid character");
                    return -1;
                }
                cfg->passwd[i] = value[i];
            }
        } else if (!strcmp(key, "uuid")) {
            strncpy(cfg->uuid, value, UUID_LEN + 1);
        } else if (!strcmp(key, "server")) {
            if (e_sock_tcp != socket_addr_format(value, &addr)) {
                log_err("system.listen address(%s) error", value);
                return -1;
            }
            memcpy(&cfg->server, &addr, sizeof(addr));
        } else if (!strcmp(key, "timer")) {
            intval = atoi(value);
            if (intval <= 0) {
                log_err("system.timer error");
            }
            cfg->timer_tv.tv_sec = intval / 1000000;
            cfg->timer_tv.tv_usec = intval % 1000000;
        } else if (!strcmp(key, "keepalive_timer")) {
            intval = atoi(value);
            if (intval <= 0) {
                log_err("system.keepalive_timer error, mast bigger than 0");
                continue;
            }
            cfg->keepalive_timer = intval;
        } else if (!strcmp(key, "aes_key")) {
            memcpy(cfg->aes_key, value, strlen(value) > AES_KEY_BYTES ? AES_KEY_BYTES : strlen(value));
        } else if (!strcmp(key, "allow")) {
            tmp = strchr(value, '+');
            if (!tmp || *(tmp + 1) == '\0') {
                log_err("error!");
                continue;
            }
            *tmp++ = '\0';
            cfg->allow_roles = ac_resize(cfg->allow_roles);
            if (!ac_proc(value, tmp, 1, &cfg->allow_roles->acs[cfg->allow_roles->cnt])) {
                cfg->allow_roles->cnt++;
            } else {
                log_err("error!");
            }
        } else if (!strcmp(key, "deny")) {
            tmp = strchr(value, '+');
            if (!tmp || *(tmp + 1) == '\0') {
                log_err("error!");
                continue;
            }
            *tmp++ = '\0';
            cfg->deny_roles = ac_resize(cfg->deny_roles);
            if (!ac_proc(value, tmp, 1, &cfg->deny_roles->acs[cfg->deny_roles->cnt])) {
                cfg->deny_roles->cnt++;
            } else {
                log_err("error!");
            }
        }
    }
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
    config.connect_slot_cnt = 512;
    config.buffer_chunk_size = BUFFER_CHUNK_SIZE;
    config.buffer_hold_max_bytes = 0x4000000;
    //主连接检查定时器定时周期300ms，断链后每重试一次延长重试时间300ms直至最大延时5秒
    config.timer_tv.tv_sec = 0;
    config.timer_tv.tv_usec = 300000;
    config.keepalive_timer = KEEPALIVE_TIMER;
    config.keepalive_timeout = KEEPALIVE_TIMEOUT;
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
        config_file = "/etc/srp/srpn.conf";
    if (config_proc(config_file, &config) < 0) {
        log_err("config process failed");
        exit(-1);
    }
    if (config.server.sin_addr.s_addr == 0) {
        log_err("server address error");
        exit(-1);
    }
    if (config.passwd[0] == '\0' || config.uuid[0] == '\0') {
        log_err("need 'password' and 'uuid'");
        exit(-1);
    }

    if (config.keepalive_timer >= config.keepalive_timeout / 3)
        config.keepalive_timer = config.keepalive_timeout / 3;

    process_rename("srp: node master process", argv);
    if (!d) {
        child_func(&config);
        while (1) {
            sleep(1);
        }
    }
    if (daemon(0, 1) < 0)
        log_err("create daemon failed, errstr:%s", strerror(errno));
    while (1) {
        errno = 0;
        pid = fork();
        if (0 > pid) {
            log_err("fork error, errstr:%s", strerror(errno));
            sleep(1);
            continue;
        }
        if (0 == pid) {
            process_rename("srp: node worker process", argv);
            child_func(&config);
        } else {
            pid = wait(&status);
            if (-1 == pid) {
                log_warn("wait() reture:%d, errstr:%s", pid, strerror(errno));
            }
            sleep(1);
        }
    }
}
