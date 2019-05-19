#include <string.h>
#include "buffer.h"
#include "common.h"

static struct {
    shead_t free;           //空闲内存链表
    int32_t allocated;      //已分配内存大小
    int32_t hold_max_bytes; //内存池可保持不释放的内存大小
    int32_t chunk_bytes;    //单次分配内存大小
} pool;

void buffer_push(shead_t *h, buffer_t *b, int32_t append) {
    assert(h && b);
    if (append)
        shead_add_tail(h, &b->list);
    else
        shead_add_head(h, &b->list);
}

buffer_t *buffer_pop(shead_t *h) {
    slist_t *list;
    assert(h);
    list = shead_pop(h);
    if (!list)
        return NULL;
    return struct_entry(list, buffer_t, list);
}

void buffer_free(buffer_t *b) {
    assert(b);
    if ((b->real + sizeof(buffer_t) - sizeof(message_t)) > pool.chunk_bytes || pool.allocated > pool.hold_max_bytes) {
        pool.allocated -= pool.chunk_bytes;
        free(b);
    } else {
        buffer_push(&pool.free, b, TRUE);
    }
}

buffer_t *buffer_alloc() {
    slist_t *list;
    buffer_t *b = NULL;
    list = shead_pop(&pool.free);
    if (list) {
        b = struct_entry(list, buffer_t, list);
    } else {
        b = malloc(pool.chunk_bytes);
        if (b)
            pool.allocated += pool.chunk_bytes;
    }
    if (!b)
        return NULL;
    memset(b, 0, sizeof(buffer_t));
    b->real = pool.chunk_bytes - sizeof(buffer_t);
    b->real &= (~(AES_BLOCK_SIZE - 1));
    b->real += sizeof(message_t);
    return b;
}

buffer_t *buffer_new(uint16_t cmd, uint64_t id, uint32_t magic) {
    buffer_t *b;
    b = buffer_alloc();
    if (!b)
        return NULL;
    b->msg.total = 0;
    b->msg.magic = magic;
    b->msg.id = id;
    b->msg.cmd = cmd;
    b->size = sizeof(message_t);
    return b;
}

void buffer_pool_init(int32_t hold_max_bytes, int32_t chunk_bytes) {
    memset(&pool, 0, sizeof(pool));
    pool.hold_max_bytes = hold_max_bytes;
    pool.chunk_bytes = chunk_bytes;
}