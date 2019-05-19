#include <mysql/mysql.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include "dbpool.h"
#include "common.h"

#define TASK_LIST_DEEPTH 256
#define THREAD_NUM 4

typedef enum { state_run = 0, state_stop_now, state_stop_wait } e_state_t;

typedef struct {
    dbpool_callback cb; //回调函数
    void *ctx;          //回调参数
    uint64_t id;        //当ctx为connect_t时，id存储dbpool_add调用时的connect_id,以在回调中判断连接是否继续有效
    char *sql;             // sql脚本内容，dbpool不会释放该指针
    unsigned short length; // sql脚本长度
} task_t;

typedef struct {
    pthread_t threads[THREAD_NUM];
    db_config_t config;
    pthread_mutex_t mutex;
    pthread_cond_t notice;
    unsigned short tail;       //任务队列尾部(指向待插入的位置)
    unsigned short head;       //任务队列头部(指向待取出的位置)
    unsigned short count;      //队列长度
    unsigned short thread_cnt; //正在运行的线程数量
    e_state_t state;
    task_t tasks[TASK_LIST_DEEPTH]; //任务队列
} pool_t;

static inline int _mysql_err(MYSQL *m, char *sql) {
    log_warn("mysql error, errno:%d, error:%s", mysql_errno(m), mysql_error(m));
    if (sql)
        log_warn("sql:%s", sql);
    if (mysql_errno(m))
        return -1;
    else
        return 0;
}

/**
 * @brief 执行sql脚本并返回调用task_t的callback函数
 *
 * @param p pool_t结构体句柄
 * @param m MYSQL句柄
 * @param t task_t句柄
 * @return int 返回-1表示错误，需要重新连接数据库
 */
static int _mysql_query(pool_t *p, MYSQL *m, task_t *t) {
    assert(p && m && t && t->sql);
    MYSQL_RES *res;

    //执行命令
    if (mysql_real_query(m, t->sql, t->length))
        return _mysql_err(m, t->sql);

    //是否有数据
    if (mysql_field_count(m) == 0)
        return 0;

    //获取结果
    res = mysql_store_result(m);
    (*t->cb)(t->ctx, t->id, res);
    if (NULL == res)
        return _mysql_err(m, t->sql);

    mysql_free_result(res);
    return 0;
}

/**
 * @brief 仅执行sql脚本，不执行回调函数
 *
 * @param p pool_t结构体句柄
 * @param m MYSQL句柄
 * @param t task_t句柄
 * @return int 返回-1表示错误，需要重新连接数据库
 */
static int _mysql_exec(pool_t *p, MYSQL *m, task_t *t) {
    assert(p && m && t && t->sql);
    int ret;

    //执行命令
    ret = mysql_real_query(m, t->sql, t->length);
    if (ret) {
        _mysql_err(m, t->sql);
        return -1;
    }
    return 0;
}

static MYSQL *_mysql_new(db_config_t *c) {
    MYSQL *mysql = mysql_init(NULL);
    if (!mysql) {
        _mysql_err(mysql, NULL);
        return NULL;
    }
    if (!mysql_real_connect(mysql, c->host, c->user, c->password, c->db, c->port, NULL, 0)) {
        _mysql_err(mysql, NULL);
        mysql_close(mysql);
        return NULL;
    }
    return mysql;
}

static void *_dbpool_worker(void *arg) {
    pool_t *p = (pool_t *)arg;
    MYSQL *mysql = NULL;
    task_t task;
    int32_t ret;
    assert(arg);

    while (1) {
        while (!mysql) {
            sleep(1);
            mysql = _mysql_new(&p->config);
        }
        pthread_mutex_lock(&(p->mutex));
        while ((p->count == 0) && (p->state == state_run))
            pthread_cond_wait(&p->notice, &p->mutex);

        if ((p->state == state_stop_now) || ((p->state == state_stop_wait) && (p->count == 0))) {
            break;
        }

        memcpy(&task, &p->tasks[p->head], sizeof(task_t));
        p->head = (p->head + 1) % TASK_LIST_DEEPTH;
        p->count--;
        pthread_mutex_unlock(&p->mutex);

        if (task.cb)
            ret = _mysql_query(p, mysql, &task);
        else
            ret = _mysql_exec(p, mysql, &task);
        free(task.sql);
        if (ret) {
            mysql_close(mysql);
            mysql = NULL;
        }
    }
    p->thread_cnt--;
    pthread_mutex_unlock(&p->mutex);
    pthread_exit(NULL);
    return (NULL);
}

dbpool_t *dbpool_create(db_config_t *config) {
    pool_t *p;
    MYSQL *mysql = NULL;
    assert(config && TASK_LIST_DEEPTH);
    mysql = _mysql_new(config);
    if (!mysql)
        return NULL;
    mysql_close(mysql);
    p = (pool_t *)malloc(sizeof(pool_t));
    if (!p)
        return NULL;
    memset(p, 0, sizeof(pool_t));
    memcpy(&p->config, config, sizeof(*config));
    p->state = state_run;
    pthread_mutex_init(&p->mutex, NULL);
    pthread_cond_init(&p->notice, NULL);
    for (int i = 0; i < THREAD_NUM; i++) {
        pthread_create(p->threads + i, NULL, _dbpool_worker, p);
        p->thread_cnt++;
    }
    return (dbpool_t *)p;
}

static void _dbpool_free(pool_t *p) {
    pthread_mutex_destroy(&p->mutex);
    pthread_cond_destroy(&p->notice);
    free(p->threads);
    free(p);
}

int dbpool_destroy(dbpool_t *sp, int now) {
    pool_t *p = (pool_t *)sp;

    if (pthread_mutex_lock(&p->mutex) != 0)
        return -1;

    do {
        if (p->state != state_run)
            break;
        if (now)
            p->state = state_stop_now;
        else
            p->state = state_stop_wait;
        if (pthread_cond_broadcast(&p->notice) != 0 || pthread_mutex_unlock(&p->mutex) != 0)
            return -2;

        for (int i = 0; i < THREAD_NUM; i++) {
            if (pthread_join(p->threads[i], NULL) != 0)
                return -3;
        }
    } while (0);

    if (!p->thread_cnt)
        _dbpool_free(p);

    return 0;
}

static int _dbpool_add_query(dbpool_t *sp, void *ctx, uint64_t id, dbpool_callback cb, char *sql,
                             unsigned short length) {
    pool_t *p = (pool_t *)sp;
    int ret = DBPOOL_STATE_SUCCESS;
    assert(sp && sql);

    if (pthread_mutex_lock(&p->mutex) != 0)
        return DBPOOL_STATE_ERROR;

    do {
        if (p->count >= TASK_LIST_DEEPTH) {
            ret = DBPOOL_STATE_FULL;
            break;
        }
        if (p->state != state_run) {
            ret = DBPOOL_STATE_STOP;
            break;
        }
        p->tasks[p->tail].cb = cb;
        p->tasks[p->tail].ctx = ctx;
        p->tasks[p->tail].id = id;
        p->tasks[p->tail].sql = sql;
        p->tasks[p->tail].length = length;
        p->tail = (p->tail + 1) % TASK_LIST_DEEPTH;
        p->count += 1;

        /* pthread_cond_broadcast */
        if (pthread_cond_signal(&p->notice) != 0) {
            ret = DBPOOL_STATE_ERROR;
            break;
        }
    } while (0);
    pthread_mutex_unlock(&p->mutex);
    return ret;
}

int dbpool_add(dbpool_t *sp, void *ctx, uint64_t id, dbpool_callback cb, const char *format, ...) {
    //初始分配1024字节，如果不足则扩倍，最大4096字节
    va_list ap;
    int size = 1024, real, ret = DBPOOL_STATE_SUCCESS;
    char *sql;
    //数据库连接池为空时表示数据库不可用，强制返回成功
    if (!sp)
        return DBPOOL_STATE_SUCCESS;
    va_start(ap, format);
    do {
        sql = (char *)malloc(size);
        if (!sql) {
            log_warn("malloc failed");
            ret = DBPOOL_STATE_ERROR;
            break;
        }

        real = vsnprintf(sql, size, format, ap);
        if (real == size - 1) {
            if (size >= 4096) {
                log_warn("sql script too long");
                ret = DBPOOL_STATE_ERROR;
                break;
            }
            free(sql);
            size <<= 1;
            continue;
        } else {
            break;
        }
    } while (1);
    va_end(ap);
    if (ret != DBPOOL_STATE_SUCCESS || (ret = _dbpool_add_query(sp, ctx, id, cb, sql, real))) {
        log_warn("add dbpool task failed, sql:%s, ret:%d", sql, ret);
        if (sql)
            free(sql);
        return ret;
    }
    return DBPOOL_STATE_SUCCESS;
}