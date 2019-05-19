#ifndef __SRP_NETWORK_H__
#define __SRP_NETWORK_H__
#include <linux/tcp.h>
#include <stdint.h>

typedef enum {
    e_sock_err = 0, //未知或错误地址
    e_sock_tcp,     // tcp地址tcp://ip_addr:port
    e_sock_udp      // udp地址udp://ip_addr:port
} e_sock_t;

void close_socket(int32_t fd);
int32_t set_nonblock(int32_t fd);
int32_t listen_port(struct sockaddr_in *addr, int reuseaddr);
int32_t connect_port(struct sockaddr_in *addr, int async, int option);
void get_ip_by_name(const char *host, char *ip);
e_sock_t socket_addr_format(const char *host, struct sockaddr_in *addr_in);

#endif
