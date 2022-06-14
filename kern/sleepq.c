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

struct sleepq_bucket
{
  __cacheline_aligned struct spinlock lock;
  struct hlist sleepqs;
};

struct sleepq_waiter
{
  struct list node;
  struct thread *thread;
  bool pending_wakeup;
};

/*
 * Waiters are queued in FIFO order and inserted at the head of the
 * list of waiters. The pointer to the "oldest" waiter is used as
 * a marker between threads waiting for a signal/broadcast (from the
 * beginning up to and including the oldest waiter) and threads pending
 * for wake-up (all the following threads up to the end of the list).
 */
struct sleepq
{
  __cacheline_aligned struct sleepq_bucket *bucket;
  struct hlist_node node;
  const void *sync_obj;
  struct list waiters;
  struct sleepq_waiter *oldest_waiter;
  struct sleepq *next_free;
};

#define SLEEPQ_HTABLE_SIZE        128
#define SLEEPQ_COND_HTABLE_SIZE   64

#if !ISP2(SLEEPQ_HTABLE_SIZE) || !ISP2(SLEEPQ_COND_HTABLE_SIZE)
  #error "hash table size must be a power of two"
#endif

#define SLEEPQ_HTABLE_MASK        (SLEEPQ_HTABLE_SIZE - 1)
#define SLEEPQ_COND_HTABLE_MASK   (SLEEPQ_COND_HTABLE_SIZE - 1)

static struct sleepq_bucket sleepq_htable[SLEEPQ_HTABLE_SIZE];
static struct sleepq_bucket sleepq_cond_htable[SLEEPQ_COND_HTABLE_SIZE];

static struct kmem_cache sleepq_cache;

static uintptr_t
sleepq_hash (const void *addr)
{
  return (((uintptr_t) addr >> 8) ^ (uintptr_t) addr);
}

static void
sleepq_waiter_init (struct sleepq_waiter *waiter, struct thread *thread)
{
  waiter->thread = thread;
  waiter->pending_wakeup = false;
}

static bool
sleepq_waiter_pending_wakeup (const struct sleepq_waiter *waiter)
{
  return (waiter->pending_wakeup);
}

static void
sleepq_waiter_set_pending_wakeup (struct sleepq_waiter *waiter)
{
  waiter->pending_wakeup = true;
}

static void
sleepq_waiter_wakeup (struct sleepq_waiter *waiter)
{
  if (sleepq_waiter_pending_wakeup (waiter))
    thread_wakeup (waiter->thread);
}

static bool
sleepq_init_state_valid (const struct sleepq *sleepq)
{
  return (!sleepq->bucket &&
          !sleepq->sync_obj &&
          list_empty (&sleepq->waiters) &&
          !sleepq->oldest_waiter &&
          !sleepq->next_free);
}

static void
sleepq_use (struct sleepq *sleepq, const void *sync_obj)
{
  assert (!sleepq->sync_obj);
  sleepq->sync_obj = sync_obj;
}

static void
sleepq_unuse (struct sleepq *sleepq)
{
  assert (sleepq->sync_obj);
  sleepq->sync_obj = NULL;
}

static bool
sleepq_in_use (const struct sleepq *sleepq)
{
  return (sleepq->sync_obj != NULL);
}

static bool
sleepq_in_use_by (const struct sleepq *sleepq, const void *sync_obj)
{
  return (sleepq->sync_obj == sync_obj);
}

static void
sleepq_bucket_init (struct sleepq_bucket *bucket)
{
  spinlock_init (&bucket->lock);
  hlist_init (&bucket->sleepqs);
}

static struct sleepq_bucket*
sleepq_bucket_get_cond (const void *sync_obj)
{
  uintptr_t index = sleepq_hash (sync_obj) & SLEEPQ_COND_HTABLE_MASK;
  assert (index < ARRAY_SIZE (sleepq_cond_htable));
  return (&sleepq_cond_htable[index]);
}

static struct sleepq_bucket*
sleepq_bucket_get (const void *sync_obj, bool condition)
{
  if (condition)
    return sleepq_bucket_get_cond (sync_obj);

  uintptr_t index = sleepq_hash (sync_obj) & SLEEPQ_HTABLE_MASK;
  assert (index < ARRAY_SIZE (sleepq_htable));
  return (&sleepq_htable[index]);
}

static void
sleepq_bucket_add (struct sleepq_bucket *bucket, struct sleepq *sleepq)
{
  assert (!sleepq->bucket);
  sleepq->bucket = bucket;
  hlist_insert_head (&bucket->sleepqs, &sleepq->node);
}

static void
sleepq_bucket_remove (struct sleepq_bucket *bucket, struct sleepq *sleepq)
{
  assert (sleepq->bucket == bucket);
  sleepq->bucket = NULL;
  hlist_remove (&sleepq->node);
}

static struct sleepq*
sleepq_bucket_lookup (const struct sleepq_bucket *bucket, const void *sync_obj)
{
  struct sleepq *sleepq;
  hlist_for_each_entry (&bucket->sleepqs, sleepq, node)
    if (sleepq_in_use_by (sleepq, sync_obj))
      {
        assert (sleepq->bucket == bucket);
        return (sleepq);
      }

  return (NULL);
}

static void
sleepq_ctor (void *ptr)
{
  struct sleepq *sleepq = ptr;
  sleepq->bucket = NULL;
  sleepq->sync_obj = NULL;
  list_init (&sleepq->waiters);
  sleepq->oldest_waiter = NULL;
  sleepq->next_free = NULL;
}

static int __init
sleepq_setup (void)
{
  for (size_t i = 0; i < ARRAY_SIZE (sleepq_htable); i++)
    sleepq_bucket_init (&sleepq_htable[i]);

  for (size_t i = 0; i < ARRAY_SIZE (sleepq_cond_htable); i++)
    sleepq_bucket_init (&sleepq_cond_htable[i]);

  kmem_cache_init (&sleepq_cache, "sleepq", sizeof (struct sleepq),
                   CPU_L1_SIZE, sleepq_ctor, 0);
  return (0);
}

INIT_OP_DEFINE (sleepq_setup,
                INIT_OP_DEP (kmem_setup, true));

struct sleepq*
sleepq_create (void)
{
  struct sleepq *sleepq = kmem_cache_alloc (&sleepq_cache);
  if (! sleepq)
    return (NULL);

  assert (sleepq_init_state_valid (sleepq));
  return (sleepq);
}

void
sleepq_destroy (struct sleepq *sleepq)
{
  assert (sleepq_init_state_valid (sleepq));
  kmem_cache_free (&sleepq_cache, sleepq);
}

static struct sleepq*
sleepq_acquire_common (const void *sync_obj, bool condition, unsigned long *flags)
{
  assert (sync_obj);

  _Auto bucket = sleepq_bucket_get (sync_obj, condition);

  if (flags)
    spinlock_lock_intr_save (&bucket->lock, flags);
  else
    spinlock_lock (&bucket->lock);

  _Auto sleepq = sleepq_bucket_lookup (bucket, sync_obj);
  if (! sleepq)
    {
      if (flags)
        spinlock_unlock_intr_restore (&bucket->lock, *flags);
      else
        spinlock_unlock (&bucket->lock);
    }

  return (sleepq);
}

static struct sleepq*
sleepq_tryacquire_common (const void *sync_obj, bool condition,
                          unsigned long *flags)
{
  assert (sync_obj);

  _Auto bucket = sleepq_bucket_get (sync_obj, condition);
  int error = flags ? spinlock_trylock_intr_save (&bucket->lock, flags) :
                      spinlock_trylock (&bucket->lock); 

  if (error)
    return (NULL);

  _Auto sleepq = sleepq_bucket_lookup (bucket, sync_obj);
  if (! sleepq)
    {
      if (flags)
        spinlock_unlock_intr_restore (&bucket->lock, *flags);
      else
        spinlock_unlock (&bucket->lock);
    }

  return (sleepq);
}

struct sleepq*
sleepq_acquire (const void *sync_obj, bool condition)
{
  return (sleepq_acquire_common (sync_obj, condition, NULL));
}

struct sleepq *
sleepq_tryacquire (const void *sync_obj, bool condition)
{
  return (sleepq_tryacquire_common (sync_obj, condition, NULL));
}

void
sleepq_release (struct sleepq *sleepq)
{
  spinlock_unlock (&sleepq->bucket->lock);
}

struct sleepq*
sleepq_acquire_intr_save (const void *sync_obj, bool condition,
                          unsigned long *flags)
{
  return (sleepq_acquire_common (sync_obj, condition, flags));
}

struct sleepq *
sleepq_tryacquire_intr_save (const void *sync_obj, bool condition,
                             unsigned long *flags)
{
  return (sleepq_tryacquire_common (sync_obj, condition, flags));
}

void
sleepq_release_intr_restore (struct sleepq *sleepq, unsigned long flags)
{
  spinlock_unlock_intr_restore (&sleepq->bucket->lock, flags);
}

static void
sleepq_push_free (struct sleepq *sleepq, struct sleepq *free_sleepq)
{
  assert (!free_sleepq->next_free);
  free_sleepq->next_free = sleepq->next_free;
  sleepq->next_free = free_sleepq;
}

static struct sleepq*
sleepq_pop_free (struct sleepq *sleepq)
{
  struct sleepq *free_sleepq = sleepq->next_free;
  if (! free_sleepq)
    return (NULL);

  sleepq->next_free = free_sleepq->next_free;
  free_sleepq->next_free = NULL;
  return (free_sleepq);
}

static struct sleepq*
sleepq_lend_common (const void *sync_obj, bool condition, unsigned long *flags)
{
  assert (sync_obj);

  _Auto sleepq = thread_sleepq_lend ();
  assert (sleepq_init_state_valid (sleepq));

  _Auto bucket = sleepq_bucket_get (sync_obj, condition);

  if (flags)
    spinlock_lock_intr_save (&bucket->lock, flags);
  else
    spinlock_lock (&bucket->lock);

  struct sleepq *prev = sleepq_bucket_lookup (bucket, sync_obj);

  if (! prev)
    {
      sleepq_use (sleepq, sync_obj);
      sleepq_bucket_add (bucket, sleepq);
    }
  else
    {
      sleepq_push_free (prev, sleepq);
      sleepq = prev;
    }

  return (sleepq);
}

static void
sleepq_return_common (struct sleepq *sleepq, unsigned long *flags)
{
  assert (sleepq_in_use (sleepq));

  _Auto bucket = sleepq->bucket;
  _Auto free_sleepq = sleepq_pop_free (sleepq);

  if (! free_sleepq)
    {
      sleepq_bucket_remove (bucket, sleepq);
      sleepq_unuse (sleepq);
      free_sleepq = sleepq;
    }

  if (flags)
    spinlock_unlock_intr_restore (&bucket->lock, *flags);
  else
    spinlock_unlock (&bucket->lock);

  assert (sleepq_init_state_valid (free_sleepq));
  thread_sleepq_return (free_sleepq);
}

struct sleepq*
sleepq_lend (const void *sync_obj, bool condition)
{
  return (sleepq_lend_common (sync_obj, condition, NULL));
}

void
sleepq_return (struct sleepq *sleepq)
{
  sleepq_return_common (sleepq, NULL);
}

struct sleepq*
sleepq_lend_intr_save (const void *sync_obj, bool condition,
                       unsigned long *flags)
{
  return (sleepq_lend_common (sync_obj, condition, flags));
}

void
sleepq_return_intr_restore (struct sleepq *sleepq, unsigned long flags)
{
  sleepq_return_common (sleepq, &flags);
}

static void
sleepq_shift_oldest_waiter (struct sleepq *sleepq)
{
  assert (sleepq->oldest_waiter);

  struct list *node = list_prev (&sleepq->oldest_waiter->node);
  sleepq->oldest_waiter = list_end (&sleepq->waiters, node) ?
    NULL : list_entry (node, struct sleepq_waiter, node);
}

static void
sleepq_add_waiter (struct sleepq *sleepq, struct sleepq_waiter *waiter)
{
  list_insert_head (&sleepq->waiters, &waiter->node);
  if (!sleepq->oldest_waiter)
    sleepq->oldest_waiter = waiter;
}

static void
sleepq_remove_waiter (struct sleepq *sleepq, struct sleepq_waiter *waiter)
{
  if (sleepq->oldest_waiter == waiter)
    sleepq_shift_oldest_waiter (sleepq);

  list_remove (&waiter->node);
}

static struct sleepq_waiter*
sleepq_get_last_waiter (struct sleepq *sleepq)
{
  return (list_empty (&sleepq->waiters) ?
    NULL : list_last_entry (&sleepq->waiters, struct sleepq_waiter, node));
}

bool
sleepq_empty (const struct sleepq *sleepq)
{
  return (list_empty (&sleepq->waiters));
}

static int
sleepq_wait_common (struct sleepq *sleepq, const char *wchan,
                    bool timed, uint64_t ticks)
{
  struct sleepq_waiter waiter;
  struct thread *thread = thread_self ();

  sleepq_waiter_init (&waiter, thread);
  sleepq_add_waiter (sleepq, &waiter);

  int error;

  do
    {
      if (!timed)
        {
          thread_sleep (&sleepq->bucket->lock, sleepq->sync_obj, wchan);
          error = 0;
        }
      else
        {
          error = thread_timedsleep (&sleepq->bucket->lock, sleepq->sync_obj,
                                     wchan, ticks);

          if (error)
            {
              if (sleepq_waiter_pending_wakeup (&waiter))
                error = 0;
              else
                break;
            }
        }
    }
  while (!sleepq_waiter_pending_wakeup (&waiter));

  sleepq_remove_waiter (sleepq, &waiter);

  /*
   * Chain wake-ups here to prevent broadacasting from walking a list
   * with preemption disabled. Note that this doesn't guard against
   * the thundering herd effect for condition variables.
   */
  struct sleepq_waiter *next = sleepq_get_last_waiter (sleepq);

  /*
   * Checking against the oldest waiter is enough as waiters are awoken
   * in strict FIFO order.
   */
  if (next && next != sleepq->oldest_waiter)
    {
      sleepq_waiter_set_pending_wakeup (next);
      sleepq_waiter_wakeup (next);
    }

  return (error);
}

void
sleepq_wait (struct sleepq *sleepq, const char *wchan)
{
  int error = sleepq_wait_common (sleepq, wchan, false, 0);
  assert (!error);
}

int
sleepq_timedwait (struct sleepq *sleepq, const char *wchan, uint64_t ticks)
{
  return (sleepq_wait_common (sleepq, wchan, true, ticks));
}

void
sleepq_signal (struct sleepq *sleepq)
{
  struct sleepq_waiter *waiter = sleepq->oldest_waiter;
  if (! waiter)
    return;

  sleepq_shift_oldest_waiter (sleepq);
  sleepq_waiter_set_pending_wakeup (waiter);
  sleepq_waiter_wakeup (waiter);
}

void
sleepq_broadcast (struct sleepq *sleepq)
{
  struct sleepq_waiter *waiter = sleepq->oldest_waiter;
  if (! waiter)
    return;

  sleepq->oldest_waiter = NULL;
  sleepq_waiter_set_pending_wakeup (waiter);
  sleepq_waiter_wakeup (waiter);
}
