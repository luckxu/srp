#ifndef __SRP_MESSAGE_H__
#define __SRP_MESSAGE_H__
#include "common.h"
#include <stdint.h>

//应用端和服务端请求命令字,REQ为上行命令，ASK为下行命令
#define MSG_CMD_RSAPUB_PUSH_REQ (uint16_t)0x01          //rsa公钥上传请求
#define MSG_CMD_AESKEY_ASK      (uint16_t)0x02          //aes密码下发回应
#define MSG_CMD_LOGIN_REQ       (uint16_t)0x03          //登录服务器请求
#define MSG_CMD_LOGIN_ASK       (uint16_t)0x04          //登录服务器回应
#define MSG_CMD_CLOSED_RA       (uint16_t)0x05          //客户端断开回应(双向复用)
#define MSG_CMD_NEWCONN_ASK     (uint16_t)0x06          //新连接
#define MSG_CMD_DATA_REQ        (uint16_t)0x07          //上行数据
#define MSG_CMD_DATA_ASK        (uint16_t)0x08          //下行数据
#define MSG_CMD_KEEPALIVE_REQ   (uint16_t)0x09          //节点上行心跳消息

typedef struct _srp_t srp_t;
//客户端登录消息
typedef struct {
    char uuid[UUID_LEN + 1];
    char passwd[PASSWD_LEN + 1];
} message_login_req_t;

//客户端登录回应
typedef struct {
    uint16_t result : 1;
    uint16_t tcp_nodelay : 1;
} message_login_ask_t;

typedef struct {
    conn_addr_t forward;
} message_newconn_t;

#endif
