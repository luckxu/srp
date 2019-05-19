#ifndef __SRP_LIST_H__
#define __SRP_LIST_H__
#include <assert.h>
#include <stdio.h>

typedef struct _dlist_t {
    struct _dlist_t *next;
    struct _dlist_t *prev;
} dlist_t;

typedef struct _slist_t {
    struct _slist_t *next;
} slist_t;

typedef struct _shead_t {
    struct _slist_t *tail;
    struct _slist_t *head;
} shead_t;

static inline void dlist_init(dlist_t *l) { l->next = l->prev = l; }

static inline void dlist_add_after(dlist_t *h, dlist_t *l) {
    l->next = h;
    l->prev = h->prev;
    h->prev->next = l;
    h->prev = l;
}

static inline void dlist_add_before(dlist_t *h, dlist_t *l) {
    l->next = h->next;
    l->prev = h;
    h->next->prev = l;
    h->next = l;
}

static inline int dlist_isempty(dlist_t *l) { return l->next == l; }

static inline void dlist_remove(dlist_t *l) {
    l->prev->next = l->next;
    l->next->prev = l->prev;
}

static inline dlist_t *dlist_pop(dlist_t *h) {
    dlist_t *l = h->next;
    if (!l || l == h)
        return NULL;
    h->next = l->next;
    l->next->prev = h;
    l->next = l->prev = l;
    return l;
}

#define dlist_for(h, l) for (l = h->next; l != h; l = l->next)

static inline void slist_init(slist_t *l) { l->next = NULL; }

static inline int slist_isempty(slist_t *l) { return l->next == NULL; }

static inline void slist_push(slist_t *h, slist_t *l) {
    l->next = h->next;
    h->next = l;
}

static inline slist_t *slist_pop(slist_t *h) {
    slist_t *l;
    l = h->next;
    if (l)
        h->next = l->next;
    return l;
}

static inline void shead_init(shead_t *h) { h->tail = h->head = NULL; }

static inline int shead_isempty(shead_t *h) { return h->head == NULL; }

static inline void shead_add_tail(shead_t *h, slist_t *l) {
    l->next = NULL;
    if (h->tail)
        h->tail->next = l;
    else
        h->head = l;
    h->tail = l;
}

static inline void shead_add_head(shead_t *h, slist_t *l) {
    l->next = h->head;
    h->head = l;
    if (!h->tail)
        h->tail = l;
}

static inline slist_t *shead_pop(shead_t *h) {
    slist_t *l = h->head;
    if (l) {
        if (h->head == h->tail)
            h->head = h->tail = NULL;
        else
            h->head = h->head->next;
        l->next = NULL;
    }
    return l;
}

#define struct_entry(ptr, type, member) ((type *)((char *)(ptr) - (unsigned long)(&((type *)0)->member)))

#endif