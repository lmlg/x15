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
 * Generic sleep queues.
 *
 * Sleep queues are used to build sleeping synchronization primitives
 * such as mutexes and condition variables.
 */

#ifndef KERN_SLEEPQ_H
#define KERN_SLEEPQ_H

#include <stdbool.h>
#include <stdint.h>

#include <kern/init.h>
#include <kern/sync.h>

struct sleepq;

/*
 * Create/destroy a sleep queue.
 */
struct sleepq * sleepq_create(void);
void sleepq_destroy(struct sleepq *sleepq);

/*
 * Acquire/release a sleep queue.
 *
 * Acquiring a sleep queue serializes all access and disables preemption.
 *
 * If no sleep queue has been lent for the synchronization key, NULL
 * is returned. Note that, in the case of the non-blocking variant,
 * the call may also return NULL if internal state shared by unrelated
 * synchronization key is locked.
 */
struct sleepq * sleepq_acquire_key(const struct sync_key *key);
struct sleepq * sleepq_tryacquire_key(const struct sync_key *key);

static inline struct sleepq *
sleepq_acquire(const void *sync_obj)
{
    struct sync_key key;
    sync_key_setptr(&key, sync_obj);
    return sleepq_acquire_key(&key);
}

static inline struct sleepq *
sleepq_tryacquire(const void *sync_obj)
{
    struct sync_key key;
    sync_key_setptr(&key, sync_obj);
    return sleepq_tryacquire_key(&key);
}

void sleepq_release(struct sleepq *sleepq);

/*
 * Versions of the sleep queue acquisition functions that also disable
 * interrupts.
 */
struct sleepq * sleepq_acquire_key_intr_save(const struct sync_key *key,
                                             unsigned long *flags);
struct sleepq * sleepq_tryacquire_key_intr_save(const struct sync_key *key,
                                                unsigned long *flags);

static inline struct sleepq *
sleepq_acquire_intr_save(const void *sync_obj, unsigned long *flags)
{
    struct sync_key key;
    sync_key_setptr(&key, sync_obj);
    return sleepq_acquire_key_intr_save(&key, flags);
}

static inline struct sleepq *
sleepq_tryacquire_intr_save(const void *sync_obj, unsigned long *flags)
{
    struct sync_key key;
    sync_key_setptr(&key, sync_obj);
    return sleepq_tryacquire_key_intr_save(&key, flags);
}

void sleepq_release_intr_restore(struct sleepq *sleepq,
                                 unsigned long flags);

/*
 * Lend/return a sleep queue.
 *
 * Most often, a thread lends its private sleep queue to the sleepq
 * module in order to prepare its sleep. The sleep queue obtained
 * on lending is either the thread's queue, or an already existing
 * queue for this synchronization key if another thread is waiting.
 *
 * When multiple threads lend their sleep queue for the same synchronization
 * key, the extra queues lent are kept in an internal free list, used
 * when threads are awoken to return a queue to them. As a result, the
 * sleep queue returned may not be the one lent.
 *
 * The sleep queue obtained when lending is automatically acquired.
 */
struct sleepq * sleepq_lend_key(const struct sync_key *key);

static inline struct sleepq *
sleepq_lend(const void *sync_obj)
{
    struct sync_key key;
    sync_key_setptr(&key, sync_obj);
    return sleepq_lend_key(&key);
}

void sleepq_return(struct sleepq *sleepq);

/*
 * Versions of the sleep queue lending functions that also disable
 * interrupts.
 */
struct sleepq * sleepq_lend_key_intr_save(const struct sync_key *key,
                                          unsigned long *flags);

static inline struct sleepq *
sleepq_lend_intr_save(const void *sync_obj, unsigned long *flags)
{
    struct sync_key key;
    sync_key_setptr(&key, sync_obj);
    return sleepq_lend_key_intr_save(&key, flags);
}

void sleepq_return_intr_restore(struct sleepq *sleepq, unsigned long flags);

/*
 * Return true if the given sleep queue has no waiters.
 *
 * The sleep queue must be acquired when calling this function.
 */
bool sleepq_empty(const struct sleepq *sleepq);

/*
 * Wait for a wake-up on the given sleep queue.
 *
 * The sleep queue must be lent when calling this function. It is
 * released and later reacquired before returning from this function.
 *
 * The calling thread is considered a waiter as long as it didn't
 * reacquire the sleep queue. This means that signalling a sleep queue
 * has no visible effect on the number of waiters until the queue is
 * released, e.g. if a single thread is waiting and another signals
 * the queue, the queue is not immediately considered empty.
 *
 * When bounding the duration of the wait, the caller must pass an absolute
 * time in ticks, and ETIMEDOUT is returned if that time is reached before
 * the sleep queue is signalled.
 */
void sleepq_wait(struct sleepq *sleepq, const char *wchan);
int sleepq_timedwait(struct sleepq *sleepq, const char *wchan, uint64_t ticks);

/*
 * Wake up a thread waiting on the given sleep queue, if any.
 *
 * The sleep queue must be acquired when calling this function.
 * A sleep queue may be signalled from interrupt context.
 *
 * Since a sleep queue must be lent (and in turn is automatically
 * acquired) when waiting, and acquired in order to signal it,
 * wake-ups are serialized and cannot be missed.
 *
 * At least one thread is awoken if any threads are waiting on the sleep
 * queue.
 *
 * Broadcasting a sleep queue wakes up all waiting threads.
 */
void sleepq_signal(struct sleepq *sleepq);
void sleepq_broadcast(struct sleepq *sleepq);

/*
 * Rearrange threads waiting on a key so that they start waiting on a new one.
 *
 * A single thread may be woken before requeueing, and it's possible to move
 * all, or just one thread from the source to the destination.
 */
int sleepq_move_key(const struct sync_key *src_key,
                    const struct sync_key *dst_key,
                    bool wake_one, bool move_all);

static inline int
sleepq_move(const void *src_addr, const void *dst_addr,
            bool wake_one, bool move_all)
{
    struct sync_key src_key, dst_key;

    sync_key_setptr(&src_key, src_addr);
    sync_key_setptr(&dst_key, dst_addr);
    return sleepq_move_key(&src_key, &dst_key, wake_one, move_all);
}

/*
 * This init operation provides :
 *  - sleepq creation
 *  - module fully initialized
 */
INIT_OP_DECLARE(sleepq_setup);

#endif /* KERN_SLEEPQ_H */
