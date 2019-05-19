#ifndef __SRP_COMMON_H__
#define __SRP_COMMON_H__

#include <arpa/inet.h>
#include <assert.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#define TRUE 1
#define FALSE 0

#define RSA_ENCRYPT_CHUNK_BYTES 244 // openssl rsa2048算法加密时每片数据长度
#define RSA_DECRYPT_CHUNK_BYTES 256 // openssl rsa2048算法解密时每片数据长度
#define SIGN_CHUNK_BYTES 256        //签名字段长度

#define RSA_KEY_BITS 2048                // rsa密钥长度
#define AES_KEY_BITS 128                 // AES密钥长度
#define AES_KEY_BYTES 16                 // AES密钥长度
#define PROXY_AES_KEY "7cb10dfcd201f1da" // AES默认密钥

//默认服务端监听地址
#define DEFAULT_LISTEN_ADDR "tcp://0.0.0.0:511"

#define KEEPALIVE_TIMEOUT 120 //超时时长，检测到应用端超过此时间发送心跳则关闭连接
#define KEEPALIVE_TIMER 60    //服务端定时周期(检查心跳超时、向数据库上报节点流量等状态等)

//默认缓存大小
#define BUFFER_CHUNK_SIZE 4096 //单个缓存大小(含头部等信息)，16字节对齐
//消息幻数
#define MSG_MAGIC 0xC8D7

#define UUID_LEN 32   //节点连接标识字节长度
#define PASSWD_LEN 32 //节点连接密码字节长度
#define IP_LEN 15     // IP地址字节长度

#define MAP_OPTION_CONNECT_UDP 0x00000001 // UDP传输属性值，客户端与节点采用UDP传输
#define MAP_OPTION_CONNECT_DELAY 0x00000002 //延迟连接属性值，客户端连接请求延迟到接收到客户端消息后发送至节点。
#define MAP_OPTION_CONNECT_DELAY_NAME "connect_delay" //延迟连接属性名

typedef struct {
    struct sockaddr_in addr;
    // 扩展属性
    // connect_delay: 延迟连接，将客户端连接请求延迟到接收到客户端消息后发送至节点。
    unsigned int option;
} conn_addr_t;

//地址映射表
typedef struct {
    int32_t forward_id; //数据库proxy_forward.id
    uint32_t expire_at; //监听有效期，为0表示不过期
    conn_addr_t listen;
    conn_addr_t forward;
} conn_map_t;

//连接扩展信息
typedef struct {
    uint16_t cnt;
    conn_map_t maps[0];
} conn_extend_t;

typedef enum {
    e_ret_success = 0, //正常状态
    e_ret_tryagain,    //需要重试
    e_ret_wait,        //条件不足，一般需要等待
    e_ret_error        //发生错误
} e_ret_t;

typedef struct rsa_keys {
    uint8_t *pub_str;
    RSA *pri_rsa;
    RSA *pub_rsa;
} rsa_keys_t;

typedef struct aes_keys {
    AES_KEY enc_aes;
    AES_KEY dec_aes;
    uint8_t key[AES_KEY_BYTES];
} aes_keys_t;

//基本消息帧格式，data部分由连接协商的aes密钥加密
typedef struct {
    uint16_t total; // data部分(含)的数据包加密后的总长，当前要求总长不得大于缓存空间大小
    uint16_t cmd;   //消息命令字
    uint16_t magic; // MSG_HEADER_MAGIC
    uint16_t padding : 5; // AES加密时填充字符数
    uint64_t id;          //连接ID，双向依据ID匹配收端连接句柄
    uint8_t data[0];      //数据
} message_t;

typedef struct {
    uint32_t version;
} system_info_t;

typedef enum {
    log_level_error,
    log_level_warn,
    log_level_info,
    log_level_debug,
    log_level_end,
} log_level_t;

typedef enum {
    error_none = 0,
    error_failed = (uint32_t)1,
} error_t;

//获取当前时间 ，单位毫秒
uint64_t get_timenow(void);
void sys_init();
void set_log_level(log_level_t level);
void write_log(log_level_t level, const char *file, const char *func, const int line, const char *format, ...);
#define log_info(format, ...) write_log(log_level_info, __FILE__, __FUNCTION__, __LINE__, format, ##__VA_ARGS__)
#define log_err(format, ...) write_log(log_level_error, __FILE__, __FUNCTION__, __LINE__, format, ##__VA_ARGS__)
#define log_warn(format, ...) write_log(log_level_warn, __FILE__, __FUNCTION__, __LINE__, format, ##__VA_ARGS__)
#define log_debug(format, ...) write_log(log_level_debug, __FILE__, __FUNCTION__, __LINE__, format, ##__VA_ARGS__)

void process_rename(char *new_name, char **argv);
#endif