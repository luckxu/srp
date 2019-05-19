#ifndef __SRP_BUFFER_H__
#define __SRP_BUFFER_H__
#include <stdint.h>
#include "common.h"
#include "list.h"

typedef struct {
    slist_t list;
    int16_t start;          //起始有效地址
    int16_t real;           //实际内存大小
    int16_t size;           //已使用的内存大小
    uint16_t reserved : 15; //保留，清零
    uint16_t worked : 1;    //是否是处理过后的数据
    message_t msg;
} buffer_t;

void buffer_push(shead_t *h, buffer_t *b, int32_t append);
buffer_t *buffer_pop(shead_t *h);
void buffer_free(buffer_t *b);
buffer_t *buffer_alloc();
buffer_t *buffer_new(uint16_t cmd, uint64_t id, uint32_t magic);
void buffer_pool_init(int32_t hold_max_bytes, int32_t chunk_bytes);
#endif