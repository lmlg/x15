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
  struct sleepq *sleepq;
  bool pending_wakeup;
};

#define SLEEPQ_HTABLE_SIZE        128

#if !ISP2(SLEEPQ_HTABLE_SIZE) || !ISP2(SLEEPQ_COND_HTABLE_SIZE)
  #error "hash table size must be a power of two"
#endif

#define SLEEPQ_HTABLE_MASK        (SLEEPQ_HTABLE_SIZE - 1)

static struct sleepq_bucket sleepq_htable[SLEEPQ_HTABLE_SIZE];
static struct kmem_cache sleepq_cache;

static void
sleepq_waiter_init (struct sleepq_waiter *waiter,
                    struct thread *thread, struct sleepq *sleepq)
{
  waiter->thread = thread;
  waiter->sleepq = sleepq;
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
sleepq_waiter_wakeup (struct sleepq_waiter *waiter, struct sleepq *sleepq)
{
  if (!sleepq_waiter_pending_wakeup (waiter))
    return;

  waiter->sleepq = sleepq;
  thread_wakeup (waiter->thread);
}

static bool
sleepq_init_state_valid (const struct sleepq *sleepq)
{
  return (!sleepq->bucket &&
          sync_key_isclear (&sleepq->sync_key) &&
          list_empty (&sleepq->waiters) &&
          !sleepq->oldest_waiter &&
          !sleepq->next_free);
}

static void
sleepq_use (struct sleepq *sleepq, const union sync_key *key)
{
  assert (sync_key_isclear (&sleepq->sync_key));
  sleepq->sync_key = *key;
}

static void
sleepq_unuse (struct sleepq *sleepq)
{
  sync_key_clear (&sleepq->sync_key);
}

static bool
sleepq_in_use (const struct sleepq *sleepq)
{
  return (!sync_key_isclear (&sleepq->sync_key));
}

static bool
sleepq_in_use_by (const struct sleepq *sleepq, const union sync_key *key)
{
  return (sync_key_eq (&sleepq->sync_key, key));
}

static void
sleepq_bucket_init (struct sleepq_bucket *bucket)
{
  spinlock_init (&bucket->lock);
  hlist_init (&bucket->sleepqs);
}

static struct sleepq_bucket*
sleepq_bucket_get (const union sync_key *key)
{
  uintptr_t index = sync_key_hash (key) & SLEEPQ_HTABLE_MASK;
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
sleepq_bucket_lookup (const struct sleepq_bucket *bucket,
                      const union sync_key *key)
{
  struct sleepq *sleepq;
  hlist_for_each_entry (&bucket->sleepqs, sleepq, node)
    if (sleepq_in_use_by (sleepq, key))
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
  sync_key_clear (&sleepq->sync_key);
  list_init (&sleepq->waiters);
  sleepq->oldest_waiter = NULL;
  sleepq->next_free = NULL;
  sleepq->free_link = NULL;
}

static int __init
sleepq_setup (void)
{
  for (size_t i = 0; i < ARRAY_SIZE (sleepq_htable); i++)
    sleepq_bucket_init (&sleepq_htable[i]);

  kmem_cache_init (&sleepq_cache, "sleepq", sizeof (struct sleepq),
                   alignof (struct sleepq), sleepq_ctor, 0);
  return (0);
}

INIT_OP_DEFINE (sleepq_setup,
                INIT_OP_DEP (kmem_setup, true));

struct sleepq*
sleepq_create (void)
{
  struct sleepq *sleepq = kmem_cache_alloc (&sleepq_cache);
  assert (!sleepq || sleepq_init_state_valid (sleepq));
  return (sleepq);
}

void
sleepq_destroy (struct sleepq *sleepq)
{
  assert (sleepq_init_state_valid (sleepq));
  kmem_cache_free (&sleepq_cache, sleepq);
}

static struct sleepq*
sleepq_acquire_common (const union sync_key *key, cpu_flags_t *flags)
{
  assert (!sync_key_isclear (key));
  _Auto bucket = sleepq_bucket_get (key);

  if (flags)
    spinlock_lock_intr_save (&bucket->lock, flags);
  else
    spinlock_lock (&bucket->lock);

  _Auto sleepq = sleepq_bucket_lookup (bucket, key);
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
sleepq_tryacquire_common (const union sync_key *key, cpu_flags_t *flags)
{
  assert (!sync_key_isclear (key));
  _Auto bucket = sleepq_bucket_get (key);
  int error = flags ? spinlock_trylock_intr_save (&bucket->lock, flags) :
                      spinlock_trylock (&bucket->lock); 

  if (error)
    return (NULL);

  _Auto sleepq = sleepq_bucket_lookup (bucket, key);
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
sleepq_acquire_key (const union sync_key *key)
{
  return (sleepq_acquire_common (key, NULL));
}

struct sleepq*
sleepq_tryacquire_key (const union sync_key *key)
{
  return (sleepq_tryacquire_common (key, NULL));
}

void
sleepq_release (struct sleepq *sleepq)
{
  spinlock_unlock (&sleepq->bucket->lock);
}

struct sleepq*
sleepq_acquire_key_intr (const union sync_key *key, cpu_flags_t *flags)
{
  return (sleepq_acquire_common (key, flags));
}

struct sleepq*
sleepq_tryacquire_key_intr (const union sync_key *key, cpu_flags_t *flags)
{
  return (sleepq_tryacquire_common (key, flags));
}

void
sleepq_release_intr_restore (struct sleepq *sleepq, cpu_flags_t flags)
{
  spinlock_unlock_intr_restore (&sleepq->bucket->lock, flags);
}

static void
sleepq_push_free (struct sleepq *sleepq, struct sleepq *free_sleepq)
{
  assert (!free_sleepq->next_free);
  free_sleepq->next_free = sleepq->next_free;
  if (!sleepq->next_free)
    sleepq->free_link = &free_sleepq->next_free;

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

  if (!sleepq->next_free)
    sleepq->free_link = NULL;

  return (free_sleepq);
}

static struct sleepq*
sleepq_lend_common (const union sync_key *key, cpu_flags_t *flags)
{
  assert (!sync_key_isclear (key));
  _Auto self = thread_self ();
  _Auto sleepq = thread_sleepq_lend (self);
  assert (sleepq_init_state_valid (sleepq));

  _Auto bucket = sleepq_bucket_get (key);
  self->wchan_addr = bucket;

  if (flags)
    spinlock_lock_intr_save (&bucket->lock, flags);
  else
    spinlock_lock (&bucket->lock);

  struct sleepq *prev = sleepq_bucket_lookup (bucket, key);

  if (! prev)
    {
      sleepq_use (sleepq, key);
      sleepq_bucket_add (bucket, sleepq);
    }
  else
    {
      sleepq_push_free (prev, sleepq);
      sleepq = prev;
    }

  self->wchan_addr = NULL;
  return (sleepq);
}

static void
sleepq_return_common (struct sleepq *sleepq, cpu_flags_t *flags)
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
sleepq_lend_key (const union sync_key *key)
{
  return (sleepq_lend_common (key, NULL));
}

void
sleepq_return (struct sleepq *sleepq)
{
  sleepq_return_common (sleepq, NULL);
}

struct sleepq*
sleepq_lend_key_intr (const union sync_key *key, cpu_flags_t *flags)
{
  return (sleepq_lend_common (key, flags));
}

void
sleepq_return_intr_restore (struct sleepq *sleepq, cpu_flags_t flags)
{
  sleepq_return_common (sleepq, &flags);
}

static void
sleepq_shift_oldest_waiter (struct sleepq *sleepq)
{
  assert (sleepq->oldest_waiter);

  struct list *node = list_next (&sleepq->oldest_waiter->node);
  sleepq->oldest_waiter = list_end (&sleepq->waiters, node) ?
    NULL : list_entry (node, struct sleepq_waiter, node);
}

static void
sleepq_add_waiter (struct sleepq *sleepq, struct sleepq_waiter *waiter)
{
  list_insert_tail (&sleepq->waiters, &waiter->node);
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
    NULL : list_first_entry (&sleepq->waiters, struct sleepq_waiter, node));
}

static int
sleepq_wait_common (struct sleepq_waiter *waiter, const char *wchan,
                    bool timed, uint64_t ticks)
{
  _Auto sleepq = waiter->sleepq;
  struct spinlock *lock = &sleepq->bucket->lock;

  sleepq_add_waiter (sleepq, waiter);
  int error;

  do
    {
      if (! timed)
        {
          thread_sleep (lock, waiter, wchan);
          error = 0;
        }
      else
        {
          error = thread_timedsleep (lock, waiter, wchan, ticks);

          if (error)
            {
              if (sleepq_waiter_pending_wakeup (waiter))
                error = 0;
              else
                break;
            }
        }
    }
  while (!sleepq_waiter_pending_wakeup (waiter));

  struct sleepq *nsq = atomic_load_rlx (&waiter->sleepq);
  if (unlikely (nsq != sleepq))
    {
      spinlock_unlock (lock);
      sleepq = nsq;
      spinlock_lock (&sleepq->bucket->lock);
    }

  sleepq_remove_waiter (sleepq, waiter);

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
      sleepq_waiter_wakeup (next, sleepq);
    }

  return (error);
}

void
sleepq_wait (struct sleepq *sleepq, const char *wchan)
{
  struct sleepq_waiter waiter;
  sleepq_waiter_init (&waiter, thread_self (), sleepq);

  int error = sleepq_wait_common (&waiter, wchan, false, 0);
  assert (! error);
}

int
sleepq_timedwait (struct sleepq *sleepq, const char *wchan, uint64_t ticks)
{
  struct sleepq_waiter waiter;
  sleepq_waiter_init (&waiter, thread_self (), sleepq);

  return (sleepq_wait_common (&waiter, wchan, true, ticks));
}

int
sleepq_wait_movable (struct sleepq **sleepq, const char *wchan,
                     uint64_t *ticksp)
{
  struct sleepq_waiter waiter;
  sleepq_waiter_init (&waiter, thread_self (), *sleepq);

  int error = ticksp ? sleepq_wait_common (&waiter, wchan, true, *ticksp) :
                       sleepq_wait_common (&waiter, wchan, false, 0);

  *sleepq = waiter.sleepq;
  return (error);
}

void
sleepq_signal (struct sleepq *sleepq)
{
  struct sleepq_waiter *waiter = sleepq->oldest_waiter;
  if (! waiter)
    return;

  sleepq_shift_oldest_waiter (sleepq);
  sleepq_waiter_set_pending_wakeup (waiter);
  sleepq_waiter_wakeup (waiter, sleepq);
}

void
sleepq_broadcast (struct sleepq *sleepq)
{
  struct sleepq_waiter *waiter = sleepq->oldest_waiter;
  if (! waiter)
    return;

  sleepq->oldest_waiter = NULL;
  sleepq_waiter_set_pending_wakeup (waiter);
  sleepq_waiter_wakeup (waiter, sleepq);
}

static inline void
sleepq_transfer (struct sleepq *dst, struct sleepq *src,
                 struct sleepq_waiter *waiter)
{
  // Remove oldest waiter from source queue.
  list_remove (&waiter->node);
  sleepq_add_waiter (dst, waiter);
  src->oldest_waiter = NULL;

  // Concatenate source and destination waiter queues.
  list_concat (&dst->waiters, &src->waiters);
  list_init (&src->waiters);

  // Transfer all the queues in the free list.
  if (src->free_link)
    {
      *src->free_link = dst->next_free;
      dst->next_free = src->next_free;
      src->next_free = NULL;
      src->free_link = NULL;
    }

  // Remove source queue from its bucket and clear its key.
  sleepq_bucket_remove (src->bucket, src);
  sleepq_unuse (src);
  sleepq_push_free (dst, src);
}

void
sleepq_move (const union sync_key *dst_key, const union sync_key *src_key,
             bool wake_one, bool move_all)
{
  assert (dst_key && !sync_key_isclear (dst_key));
  assert (src_key && !sync_key_isclear (src_key));

  if (sync_key_eq (dst_key, src_key))
    return;

  _Auto dbucket = sleepq_bucket_get (dst_key);
  _Auto sbucket = sleepq_bucket_get (src_key);

  // Lock the buckets in order to avoid any deadlocks.
  if (dbucket == sbucket)
    spinlock_lock (&dbucket->lock);
  else if (dbucket < sbucket)
    {
      spinlock_lock (&dbucket->lock);
      spinlock_lock (&sbucket->lock);
    }
  else
    {
      spinlock_lock (&sbucket->lock);
      spinlock_lock (&dbucket->lock);
    }

  _Auto dsq = sleepq_bucket_lookup (dbucket, dst_key);
  _Auto ssq = sleepq_bucket_lookup (sbucket, src_key);

  if (!dsq || !ssq || sleepq_empty (ssq))
    goto out;

  _Auto prev = ssq->oldest_waiter;

  if (move_all || list_singular (&ssq->waiters))
    // The source queue will be empty after this operation.
    sleepq_transfer (dsq, ssq, prev);
  else
    {
      sleepq_remove_waiter (ssq, prev);
      sleepq_add_waiter (dsq, prev);

      _Auto free_sleepq = sleepq_pop_free (ssq);
      if (free_sleepq)
        sleepq_push_free (dsq, free_sleepq);
    }

  if (wake_one)
    sleepq_signal (dsq);

out:
  spinlock_unlock (&dbucket->lock);
  if (dbucket != sbucket)
    spinlock_unlock (&sbucket->lock);
}
