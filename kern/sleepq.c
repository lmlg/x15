/*
 * Copyright (c) 2017-2018 Richard Braun.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * TODO Analyse hash parameters.
 */

#include <assert.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <kern/hlist.h>
#include <kern/init.h>
#include <kern/kmem.h>
#include <kern/list.h>
#include <kern/macros.h>
#include <kern/sleepq.h>
#include <kern/spinlock.h>
#include <kern/thread.h>
#include <machine/cpu.h>

struct sleepq_bucket {
    alignas(CPU_L1_SIZE) struct spinlock lock;
    struct hlist sleepqs;
};

struct sleepq_waiter {
    struct list node;
    struct thread *thread;
    bool pending_wakeup;
};

/*
 * Waiters are queued in FIFO order and inserted at the head of the
 * list of waiters.
 */
struct sleepq {
    alignas(CPU_L1_SIZE) struct sleepq_bucket *bucket;
    struct hlist_node node;
    struct sync_key key;
    struct list waiters;
    struct sleepq *next_free;
};

#define SLEEPQ_HTABLE_SIZE      128

#if !ISP2(SLEEPQ_HTABLE_SIZE)
#error "hash table size must be a power of two"
#endif /* !ISP2(SLEEPQ_HTABLE_SIZE) */

#define SLEEPQ_HTABLE_MASK      (SLEEPQ_HTABLE_SIZE - 1)

static struct sleepq_bucket sleepq_htable[SLEEPQ_HTABLE_SIZE];

static struct kmem_cache sleepq_cache;

static void
sleepq_waiter_init(struct sleepq_waiter *waiter, struct thread *thread)
{
    waiter->thread = thread;
    waiter->pending_wakeup = false;
}

static bool
sleepq_waiter_pending_wakeup(const struct sleepq_waiter *waiter)
{
    return waiter->pending_wakeup;
}

static void
sleepq_waiter_set_pending_wakeup(struct sleepq_waiter *waiter)
{
    waiter->pending_wakeup = true;
}

static void
sleepq_waiter_wakeup(struct sleepq_waiter *waiter)
{
    if (!sleepq_waiter_pending_wakeup(waiter)) {
        return;
    }

    thread_wakeup(waiter->thread);
}

static bool
sleepq_init_state_valid(const struct sleepq *sleepq)
{
    return (sleepq->bucket == NULL)
           && (sync_key_empty(&sleepq->key))
           && (list_empty(&sleepq->waiters))
           && (sleepq->next_free == NULL);
}

static void
sleepq_use(struct sleepq *sleepq, const struct sync_key *key)
{
    assert(sync_key_empty(&sleepq->key));
    sleepq->key = *key;
}

static void
sleepq_unuse(struct sleepq *sleepq)
{
    assert(!sync_key_empty(&sleepq->key));
    sync_key_init(&sleepq->key);
}

static bool
sleepq_in_use(const struct sleepq *sleepq)
{
    return !sync_key_empty(&sleepq->key);
}

static bool
sleepq_in_use_by(const struct sleepq *sleepq, const struct sync_key *key)
{
    return sync_key_eq(&sleepq->key, key);
}

static void
sleepq_bucket_init(struct sleepq_bucket *bucket)
{
    spinlock_init(&bucket->lock);
    hlist_init(&bucket->sleepqs);
}

static struct sleepq_bucket *
sleepq_bucket_get(const struct sync_key *key)
{
    uintptr_t index;

    index = sync_key_hash(key) & SLEEPQ_HTABLE_MASK;
    assert(index < ARRAY_SIZE(sleepq_htable));
    return &sleepq_htable[index];
}

static void
sleepq_bucket_add(struct sleepq_bucket *bucket, struct sleepq *sleepq)
{
    assert(sleepq->bucket == NULL);
    sleepq->bucket = bucket;
    hlist_insert_head(&bucket->sleepqs, &sleepq->node);
}

static void
sleepq_bucket_remove(struct sleepq_bucket *bucket, struct sleepq *sleepq)
{
    assert(sleepq->bucket == bucket);
    sleepq->bucket = NULL;
    hlist_remove(&sleepq->node);
}

static struct sleepq *
sleepq_bucket_lookup(const struct sleepq_bucket *bucket,
                     const struct sync_key *key)
{
    struct sleepq *sleepq;

    hlist_for_each_entry(&bucket->sleepqs, sleepq, node) {
        if (sleepq_in_use_by(sleepq, key)) {
            assert(sleepq->bucket == bucket);
            return sleepq;
        }
    }

    return NULL;
}

static void
sleepq_ctor(void *ptr)
{
    struct sleepq *sleepq;

    sleepq = ptr;
    sleepq->bucket = NULL;
    sync_key_init(&sleepq->key);
    list_init(&sleepq->waiters);
    sleepq->next_free = NULL;
}

static int __init
sleepq_setup(void)
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(sleepq_htable); i++) {
        sleepq_bucket_init(&sleepq_htable[i]);
    }

    kmem_cache_init(&sleepq_cache, "sleepq", sizeof(struct sleepq),
                    CPU_L1_SIZE, sleepq_ctor, 0);
    return 0;
}

INIT_OP_DEFINE(sleepq_setup,
               INIT_OP_DEP(kmem_setup, true));

struct sleepq *
sleepq_create(void)
{
    struct sleepq *sleepq;

    sleepq = kmem_cache_alloc(&sleepq_cache);

    if (sleepq == NULL) {
        return NULL;
    }

    assert(sleepq_init_state_valid(sleepq));
    return sleepq;
}

void
sleepq_destroy(struct sleepq *sleepq)
{
    assert(sleepq_init_state_valid(sleepq));
    kmem_cache_free(&sleepq_cache, sleepq);
}

static struct sleepq *
sleepq_acquire_common(const struct sync_key *key, unsigned long *flags)
{
    struct sleepq_bucket *bucket;
    struct sleepq *sleepq;

    assert(key != NULL && !sync_key_empty(key));

    bucket = sleepq_bucket_get(key);

    if (flags) {
        spinlock_lock_intr_save(&bucket->lock, flags);
    } else {
        spinlock_lock(&bucket->lock);
    }

    sleepq = sleepq_bucket_lookup(bucket, key);

    if (sleepq == NULL) {
        if (flags) {
            spinlock_unlock_intr_restore(&bucket->lock, *flags);
        } else {
            spinlock_unlock(&bucket->lock);
        }

        return NULL;
    }

    return sleepq;
}

static struct sleepq *
sleepq_tryacquire_common(const struct sync_key *key, unsigned long *flags)
{
    struct sleepq_bucket *bucket;
    struct sleepq *sleepq;
    int error;

    assert(key != NULL && !sync_key_empty(key));

    bucket = sleepq_bucket_get(key);

    if (flags) {
        error = spinlock_trylock_intr_save(&bucket->lock, flags);
    } else {
        error = spinlock_trylock(&bucket->lock);
    }

    if (error) {
        return NULL;
    }

    sleepq = sleepq_bucket_lookup(bucket, key);

    if (sleepq == NULL) {
        if (flags) {
            spinlock_unlock_intr_restore(&bucket->lock, *flags);
        } else {
            spinlock_unlock(&bucket->lock);
        }

        return NULL;
    }

    return sleepq;
}

struct sleepq *
sleepq_acquire_key(const struct sync_key *key)
{
    return sleepq_acquire_common(key, NULL);
}

struct sleepq *
sleepq_tryacquire_key(const struct sync_key *key)
{
    return sleepq_tryacquire_common(key, NULL);
}

void
sleepq_release(struct sleepq *sleepq)
{
    spinlock_unlock(&sleepq->bucket->lock);
}

struct sleepq *
sleepq_acquire_key_intr_save(const struct sync_key *key, unsigned long *flags)
{
    return sleepq_acquire_common(key, flags);
}

struct sleepq *
sleepq_tryacquire_key_intr_save(const struct sync_key *key,
                                unsigned long *flags)
{
    return sleepq_tryacquire_common(key, flags);
}

void
sleepq_release_intr_restore(struct sleepq *sleepq, unsigned long flags)
{
    spinlock_unlock_intr_restore(&sleepq->bucket->lock, flags);
}

static void
sleepq_push_free(struct sleepq *sleepq, struct sleepq *free_sleepq)
{
    assert(free_sleepq->next_free == NULL);
    free_sleepq->next_free = sleepq->next_free;
    sleepq->next_free = free_sleepq;
}

static struct sleepq *
sleepq_pop_free(struct sleepq *sleepq)
{
    struct sleepq *free_sleepq;

    free_sleepq = sleepq->next_free;

    if (free_sleepq == NULL) {
        return NULL;
    }

    sleepq->next_free = free_sleepq->next_free;
    free_sleepq->next_free = NULL;
    return free_sleepq;
}

static struct sleepq *
sleepq_lend_common(const struct sync_key *key, unsigned long *flags)
{
    struct sleepq_bucket *bucket;
    struct sleepq *sleepq, *prev;

    assert(key != NULL && !sync_key_empty(key));

    sleepq = thread_sleepq_lend();
    assert(sleepq_init_state_valid(sleepq));

    bucket = sleepq_bucket_get(key);

    if (flags) {
        spinlock_lock_intr_save(&bucket->lock, flags);
    } else {
        spinlock_lock(&bucket->lock);
    }

    prev = sleepq_bucket_lookup(bucket, key);

    if (prev == NULL) {
        sleepq_use(sleepq, key);
        sleepq_bucket_add(bucket, sleepq);
    } else {
        sleepq_push_free(prev, sleepq);
        sleepq = prev;
    }

    return sleepq;
}

static void
sleepq_return_common(struct sleepq *sleepq, unsigned long *flags)
{
    struct sleepq_bucket *bucket;
    struct sleepq *free_sleepq;

    assert(sleepq_in_use(sleepq));

    bucket = sleepq->bucket;
    free_sleepq = sleepq_pop_free(sleepq);

    if (free_sleepq == NULL) {
        sleepq_bucket_remove(bucket, sleepq);
        sleepq_unuse(sleepq);
        free_sleepq = sleepq;
    }

    if (flags) {
        spinlock_unlock_intr_restore(&bucket->lock, *flags);
    } else {
        spinlock_unlock(&bucket->lock);
    }

    assert(sleepq_init_state_valid(free_sleepq));
    thread_sleepq_return(free_sleepq);
}

struct sleepq *
sleepq_lend_key(const struct sync_key *key)
{
    return sleepq_lend_common(key, NULL);
}

void
sleepq_return(struct sleepq *sleepq)
{
    sleepq_return_common(sleepq, NULL);
}

struct sleepq *
sleepq_lend_key_intr_save(const struct sync_key *key, unsigned long *flags)
{
    return sleepq_lend_common(key, flags);
}

void
sleepq_return_intr_restore(struct sleepq *sleepq, unsigned long flags)
{
    sleepq_return_common(sleepq, &flags);
}

static void
sleepq_add_waiter(struct sleepq *sleepq, struct sleepq_waiter *waiter)
{
    list_insert_head(&sleepq->waiters, &waiter->node);
}

static void
sleepq_remove_waiter(struct sleepq_waiter *waiter)
{
    list_remove(&waiter->node);
}

static struct sleepq_waiter *
sleepq_get_last_waiter(struct sleepq *sleepq)
{
    if (list_empty(&sleepq->waiters)) {
        return NULL;
    }

    return list_last_entry(&sleepq->waiters, struct sleepq_waiter, node);
}

bool
sleepq_empty(const struct sleepq *sleepq)
{
    return list_empty(&sleepq->waiters);
}

static int
sleepq_wait_common(struct sleepq *sleepq, const char *wchan,
                   bool timed, uint64_t ticks)
{
    struct sleepq_waiter waiter;
    struct thread *thread;
    int error;

    thread = thread_self();
    sleepq_waiter_init(&waiter, thread);
    sleepq_add_waiter(sleepq, &waiter);

    do {
        if (!timed) {
            thread_sleep(&sleepq->bucket->lock, &sleepq->key, wchan);
            error = 0;
        } else {
            error = thread_timedsleep(&sleepq->bucket->lock, &sleepq->key,
                                      wchan, ticks);

            if (error) {
                if (sleepq_waiter_pending_wakeup(&waiter)) {
                    error = 0;
                } else {
                    break;
                }
            }
        }
    } while (!sleepq_waiter_pending_wakeup(&waiter));

    sleepq_remove_waiter(&waiter);

    return error;
}

void
sleepq_wait(struct sleepq *sleepq, const char *wchan)
{
    int error;

    error = sleepq_wait_common(sleepq, wchan, false, 0);
    assert(!error);
}

int
sleepq_timedwait(struct sleepq *sleepq, const char *wchan, uint64_t ticks)
{
    return sleepq_wait_common(sleepq, wchan, true, ticks);
}

void
sleepq_signal(struct sleepq *sleepq)
{
    struct sleepq_waiter *waiter;

    waiter = sleepq_get_last_waiter(sleepq);

    if (!waiter) {
        return;
    }

    sleepq_waiter_set_pending_wakeup(waiter);
    sleepq_waiter_wakeup(waiter);
}

void
sleepq_broadcast(struct sleepq *sleepq)
{
    struct sleepq_waiter *waiter;

    list_for_each_entry_reverse(&sleepq->waiters, waiter, node) {
        sleepq_waiter_set_pending_wakeup(waiter);
        sleepq_waiter_wakeup(waiter);
    }
}

static void
sleepq_bucket_double_lock(struct sleepq_bucket *a, struct sleepq_bucket *b)
{
    if (a == b) {
        spinlock_lock(&a->lock);
    } else if ((uintptr_t)a < (uintptr_t)b) {
        spinlock_lock(&a->lock);
        spinlock_lock(&b->lock);
    } else {
        spinlock_lock(&b->lock);
        spinlock_lock(&a->lock);
    }
}

static void
sleepq_bucket_double_unlock(struct sleepq_bucket *a, struct sleepq_bucket *b)
{
    if (a == b) {
        spinlock_unlock(&a->lock);
    } else if ((uintptr_t)a < (uintptr_t)b) {
        spinlock_unlock(&a->lock);
        spinlock_unlock(&b->lock);
    } else {
        spinlock_unlock(&b->lock);
        spinlock_unlock(&a->lock);
    }
}

int
sleepq_move(const struct sync_key *src_key, const struct sync_key *dst_key,
            bool wake_one, bool move_all)
{
    struct sleepq_bucket *src_bk, *dst_bk;
    struct sleepq *src_q, *dst_q;
    struct sleepq_waiter *waiter;
    unsigned long flags;
    int error;

    error = 0;
    waiter = NULL;
    assert(src_key != NULL && !sync_key_empty(src_key));
    assert(dst_key != NULL && !sync_key_empty(dst_key));

    thread_preempt_disable_intr_save(&flags);

    src_bk = sleepq_bucket_get(src_key);
    dst_bk = sleepq_bucket_get(dst_key);
    sleepq_bucket_double_lock(src_bk, dst_bk);

    src_q = sleepq_bucket_lookup(src_bk, src_key);
    if (!src_q || sleepq_empty(src_q)) {
        error = ESRCH;
        goto unlock;
    }

    dst_q = sleepq_bucket_lookup(dst_bk, dst_key);

    if (wake_one) {
        waiter = list_last_entry(&src_q->waiters, struct sleepq_waiter, node);
        list_remove(list_last(&src_q->waiters));
    }

    if (sync_key_eq(src_key, dst_key)) {
        goto wake;
    } else if (move_all || sleepq_empty(src_q)
        || list_singular(&src_q->waiters)) {
        /* After this operation, the source queue will be empty. */
        sleepq_bucket_remove(src_bk, src_q);
        if (dst_q == NULL) {
            /* Modify the queue so that it uses the new key. */
            sleepq_bucket_add(dst_bk, src_q);
            src_q->key = *dst_key;
        } else {
            list_concat(list_first(&dst_q->waiters), &src_q->waiters);
            sleepq_push_free(dst_q, src_q);
        }
    } else {
        if (dst_q == NULL) {
            /*
             * Since there is more than one waiter in the source queue,
             * there must also be at least a spare queue.
             */
            dst_q = sleepq_pop_free(src_q);
            assert(dst_q != NULL);
            sleepq_bucket_add(dst_bk, dst_q);
        }

        if (move_all) {
            list_concat(list_first(&dst_q->waiters), &src_q->waiters);
        } else {
            struct list *tmp;

            tmp = list_last(&src_q->waiters);
            list_remove(tmp);
            list_insert_head(&dst_q->waiters, tmp);
        }
    }

wake:
    if (waiter) {
        sleepq_waiter_set_pending_wakeup(waiter);
        sleepq_waiter_wakeup(waiter);
    }

unlock:
    sleepq_bucket_double_unlock(src_bk, dst_bk);
    thread_preempt_enable_intr_restore(flags);

    return error;
}
