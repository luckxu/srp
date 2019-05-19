#ifndef __SRP_ACCESS_CONTROL_H__
#define __SRP_ACCESS_CONTROL_H__
#include <arpa/inet.h>
#include <netinet/in.h>

typedef enum { e_ac_all = 0, e_ac_tcp, e_ac_udp } e_ac_t;

typedef struct {
    unsigned int ip;        // IP地址
    unsigned int mask;      //掩码
    unsigned short sport;   //起始端口
    unsigned short eport;   //结束端口
    unsigned int type : 2;  //连接方式, TYPE_AC_XXX
    unsigned int allow : 1; //允许还是拒绝；allow or deny
} ac_t;

typedef struct {
    int cnt;  //有效规则数量
    int size; //可容纳规则总数
    ac_t acs[0];
} ac_roles_t;

int ac_proc(char *host, char *port, int allow, ac_t *ac);
ac_roles_t *ac_resize(ac_roles_t *roles);
int ac_check(struct sockaddr_in *addr, int isudp, ac_roles_t *roles);
#endif