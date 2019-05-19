#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "access_control.h"

//初始访问控制清单大小
#define ACCESS_CONTROL_INIT_SIZE 32

int ac_proc(char *host, char *port, int allow, ac_t *ac) {
    unsigned int inv;
    char *pb;
    struct in_addr addr;
    assert(host && port && ac);
    ac->mask = 0xffffffff;
    ac->allow = !!allow;

    pb = strchr(host, '/');
    if (pb) {
        *pb++ = '\0';
        if (*pb) {
            inv = atoi(pb);
            if (inv <= 32 && inv > 0)
                ac->mask = 0xffffffff << (32 - inv);
            else if (inv != 0)
                return -1;
        } else
            return -1;
    }

    if (!inet_pton(AF_INET, host, &addr) || addr.s_addr == 0xffffffff)
        return -1;
    ac->ip = ntohl(addr.s_addr) & ac->mask;
    pb = strchr(port, '/');
    if (pb) {
        *pb++ = '\0';
        if (!strncmp(pb, "tcp", 4))
            ac->type = e_ac_tcp;
        else if (!strncmp(pb, "udp", 4))
            ac->type = e_ac_udp;
        else if (!strncmp(pb, "all", 4))
            ac->type = e_ac_all;
        else
            return -1;
    }
    pb = strchr(port, '-');
    if (pb) {
        *pb++ = '\0';
        if (*pb) {
            inv = atoi(pb);
            if (inv > 0 && inv < 0xffff)
                ac->eport = inv;
            else
                return -1;
        } else
            return -1;
    }
    inv = atoi(port);
    if (inv > 0 && inv < 0xffff)
        ac->sport = inv;
    else
        return -1;
    if (ac->eport == 0)
        ac->eport = ac->sport;
    if (ac->eport < ac->sport)
        return -1;
    return 0;
}

ac_roles_t *ac_resize(ac_roles_t *roles) {
    int size;
    if (!roles) {
        size = sizeof(ac_roles_t) + sizeof(ac_t) * ACCESS_CONTROL_INIT_SIZE;
        roles = (ac_roles_t *)malloc(size);
        if (!roles) {
            return NULL;
        }
        memset(roles, 0, size);
        roles->size = ACCESS_CONTROL_INIT_SIZE;
    } else if (roles->cnt == roles->size) {
        size = sizeof(ac_roles_t) + sizeof(ac_t) * (roles->size << 1);
        roles = (ac_roles_t *)realloc(roles, size);
        if (!roles) {
            return NULL;
        }
        roles->size <<= 1;
    }
    return roles;
}

int ac_check(struct sockaddr_in *addr, int isudp, ac_roles_t *roles) {
    ac_t *ac;
    int ip = ntohl(addr->sin_addr.s_addr);
    unsigned short port = ntohs(addr->sin_port);
    for (int i = 0; i < roles->cnt; i++) {
        ac = roles->acs + i;
        if ((ip & ac->mask) == ac->ip && ac->sport <= port && ac->eport >= port &&
            (ac->type == e_ac_all || (isudp && ac->type == e_ac_udp) || (!isudp && ac->type == e_ac_tcp)))
            return 0;
    }
    return 1;
}
