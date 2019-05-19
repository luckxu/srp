#ifndef __SRP_DBPOOL_H__
#define __SRP_DBPOOL_H__
#include <stdint.h>

#define DBPOOL_STATE_SUCCESS 0
#define DBPOOL_STATE_ERROR -1
#define DBPOOL_STATE_FULL -2
#define DBPOOL_STATE_STOP -3

typedef void (*dbpool_callback)(void *ctx, uint64_t id, void *result);

typedef struct {
    char host[128];
    char user[32];
    char password[32];
    char db[32];
    uint16_t port;
} db_config_t;

typedef void *dbpool_t;

#ifndef _NODE
dbpool_t *dbpool_create(db_config_t *config);
int dbpool_destroy(dbpool_t *sp, int now);
int dbpool_add(dbpool_t *sp, void *ctx, uint64_t id, dbpool_callback cb, const char *format, ...);
#else
#define dbpool_create(c) (NULL)
#define dbpool_destroy(s, n) 0
#define dbpool_add(sp, ctx, id, cb, f, ...)
#endif
#endif