/*
 * Copyright (c) 2023 Agustina Arzille.
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

#include <kern/clock.h>
#include <kern/futex.h>
#include <kern/sleepq.h>
#include <kern/turnstile.h>
#include <kern/unwind.h>
#include <kern/user.h>

#include <vm/map.h>
#include <vm/object.h>

#define FUTEX_DATA_SHARED   FUTEX_SHARED
#define FUTEX_DATA_WAIT     0x02
#define FUTEX_DATA_WAKE     0x04

// Operations used in 'futex_map_addr' below.
#define FUTEX_OP_CMP                0
#define FUTEX_OP_SET                1
#define FUTEX_OP_ROBUST_CLEAR       2
#define FUTEX_OP_LOCK_PI            3

struct futex_data;

/*
 * Futex operations.
 *
 * Since the operations themselves are very similar across futexes'
 * "flavors", this structure aims to encapsulate the subtleties among them.
 */

struct futex_ops
{
  void* (*acquire) (const union sync_key *);
  void (*release) (void *);
  union
    {
      int (*wait) (struct futex_data *, int, uint32_t, uint64_t);
      int (*wake) (void *, uint32_t);
    };
};

struct futex_data
{
  int *addr;
  struct vm_map *map;
  union sync_key key;
  uint32_t mode;
  void *wait_obj;
  const struct futex_ops *ops;
};

static int
futex_check_addr (int *addr)
{
  if (!user_check_range (addr, sizeof (int)))
    return (EFAULT);
  else if (((uintptr_t)addr % sizeof (int)) != 0)
    return (EINVAL);
  return (0);
}

static int
futex_key_init (union sync_key *key, struct vm_map *map,
                int *addr, uint32_t flags)
{
  if (likely (!(flags & FUTEX_SHARED)))
    /*
     * For task-local futexes the key is made up of the virtual address
     * itself and the calling thread's VM map.
     */
    sync_key_local_init (key, addr, map);
  else
    {
      /*
       * For task-shared futexes, the key is made of the <VM object, offset>
       * pair, obtained by performing a VM lookup on the virtual address.
       */

      struct vm_map_entry entry;
      int error = vm_map_lookup (map, (uintptr_t)addr, &entry);

      if (error)
        return (error);

      sync_key_shared_init (key, entry.object, entry.offset);
    }

  return (0);
}

static void*
futex_sleepq_lend (const union sync_key *key)
{
  return (sleepq_lend_key (key));
}

static void*
futex_pi_lend (const union sync_key *key)
{
  return (turnstile_lend_key (key));
}

static void
futex_sleepq_return (void *obj)
{
  sleepq_return ((struct sleepq *)obj);
}

static void
futex_pi_return (void *obj)
{
  turnstile_return ((struct turnstile *)obj);
}

static void*
futex_sleepq_acquire (const union sync_key *key)
{
  return (sleepq_acquire_key (key));
}

static void*
futex_pi_acquire (const union sync_key *key)
{
  return (turnstile_acquire_key (key));
}

static void
futex_sleepq_release (void *obj)
{
  sleepq_release ((struct sleepq *)obj);
}

static void
futex_pi_release (void *obj)
{
  turnstile_release ((struct turnstile *)obj);
  thread_propagate_priority ();
}

static int
futex_sleepq_wait (struct futex_data *data, int value __unused,
                   uint32_t flags, uint64_t ticks)
{
  uint64_t *timep = NULL;
  if (flags & FUTEX_TIMED)
    {
      timep = &ticks;
      if (!(flags & FUTEX_ABSTIME))
        ticks += clock_get_time () + 1;
    }

  return (sleepq_wait_movable ((struct sleepq **)&data->wait_obj,
                               "futex", timep));
}

static int futex_map_addr (struct futex_data *, int, int);

static int
futex_pi_wait (struct futex_data *data, int value,
               uint32_t flags, uint64_t ticks)
{
  struct thread *thr = thread_by_kuid ((uint32_t)value & FUTEX_TID_MASK);
  if (! thr)
    return (ESRCH);
  else if (thr == thread_self ())
    {
      thread_unref (thr);
      return (EALREADY);
    }

  int error;
  
  if (!(flags & FUTEX_TIMED))
    error = turnstile_wait (data->wait_obj, "futex-pi", thr);
  else
    {
      if (!(flags & FUTEX_ABSTIME))
        ticks += clock_get_time () + 1;
      error = turnstile_timedwait (data->wait_obj, "futex-pi", thr, ticks);
    }

  thread_unref (thr);
  if (error)
    return (error);

  /*
   * PI futexes have ownership semantics. In order to apply them, we
   * need to change the futex word's value after a succesful wait.
   */

  error = futex_map_addr (data, thread_id (thread_self ()), FUTEX_OP_LOCK_PI);
  if (! error)
    turnstile_own (data->wait_obj);

  return (error);
}

static int
futex_sleepq_wake (void *sleepq, uint32_t flags)
{
  if (flags & FUTEX_BROADCAST)
    sleepq_broadcast ((struct sleepq *)sleepq);
  else
    sleepq_signal ((struct sleepq *)sleepq);

  return (0);
}

static int
futex_pi_wake (void *obj, uint32_t flags)
{
  struct turnstile *turnstile = (struct turnstile *)obj;
  if (!turnstile_owned_by (turnstile, thread_self ()))
    return (EPERM);

  turnstile_disown (turnstile);
  if (flags & FUTEX_BROADCAST)
    turnstile_broadcast (turnstile);
  else
    turnstile_signal (turnstile);

  return (0);
}

// Set of operations used when waiting on a futex.
static const struct futex_ops futex_wait_ops[] =
{
  {
    .acquire = futex_sleepq_lend,
    .release = futex_sleepq_return,
    .wait    = futex_sleepq_wait
  },
  {
    .acquire = futex_pi_lend,
    .release = futex_pi_return,
    .wait    = futex_pi_wait
  }
};

// Operations used when waking futex waiters.
static const struct futex_ops futex_wake_ops[] =
{
  {
    .acquire = futex_sleepq_acquire,
    .release = futex_sleepq_release,
    .wake    = futex_sleepq_wake
  },
  {
    .acquire = futex_pi_acquire,
    .release = futex_pi_release,
    .wake    = futex_pi_wake
  }
};

static const struct futex_ops*
futex_select_ops (uint32_t flags, uint32_t mode)
{
  uint32_t idx = (flags & FUTEX_PI) / FUTEX_PI;
  return ((mode & FUTEX_DATA_WAIT) ?
          &futex_wait_ops[idx] : &futex_wake_ops[idx]);
}

static int
futex_data_init (struct futex_data *data, int *addr,
                 uint32_t flags, uint32_t mode)
{
  int error = futex_check_addr (addr);
  if (error)
    return (error);

  data->mode = mode;
  data->map = vm_map_self ();
  data->addr = addr;

  error = futex_key_init (&data->key, data->map, addr, flags);
  if (error)
    return (error);
  else if (flags & FUTEX_SHARED)
    data->mode |= FUTEX_DATA_SHARED;

  data->wait_obj = NULL;
  data->ops = futex_select_ops (flags, mode);
  return (0);
}

static void
futex_data_release (struct futex_data *data)
{
  if (!data->wait_obj)
    return;

  data->ops->release (data->wait_obj);
  data->wait_obj = NULL;
}

static void
futex_data_fini (void *arg)
{
  struct futex_data *data = arg;
  if (data->mode & FUTEX_DATA_SHARED)
    vm_object_unref (data->key.shared.object);

  futex_data_release (data);
}

static int
futex_robust_clear (int *addr, int value)
{
  while (1)
    {
      int tmp = atomic_load_rlx (addr);
      if ((tmp & FUTEX_TID_MASK) != (uint32_t)value)
        return (0);
      else if (atomic_cas_bool_rel (addr, tmp, tmp | FUTEX_OWNER_DIED))
        /*
         * Use a negative value to indicate that a wakeup is needed. This is
         * done so that it doesn't clash with any errno value.
         */
        return ((tmp & FUTEX_WAITERS) ? -1 : 0);

      cpu_pause ();
    }
}

static int
futex_map_addr (struct futex_data *data, int value, int op)
{
  int prot = op == FUTEX_OP_CMP ? VM_PROT_READ : VM_PROT_RDWR;

  struct unw_fixup fixup;
  int error = unw_fixup_save (&fixup);

  if (error)
    {
      /*
       * There was a page fault when accessing the address. Test if this
       * was simply because it needs to be paged in, and we couldn't do it
       * earlier due to us holding a spinlock, or because there was another
       * issue (like a protection error).
       */

      thread_pagefault_enable ();
      if (error != EAGAIN)
        return (error);

      // Drop the lock on the wait queue and page in the address.
      futex_data_release (data);

      cpu_flags_t flags;
      cpu_intr_save (&flags);
      error = vm_map_fault (data->map, (uintptr_t)data->addr, prot);
      cpu_intr_restore (flags);

      if (error)
        return (error);

      data->wait_obj = data->ops->acquire (&data->key);
      error = 0;
    }

  thread_pagefault_disable ();

  switch (op)
    {
      case FUTEX_OP_CMP:
        error = value == *data->addr ? 0 : EAGAIN;
        break;

      case FUTEX_OP_SET:
        *data->addr = value;
        break;

      case FUTEX_OP_ROBUST_CLEAR:
        error = futex_robust_clear (data->addr, value);
        break;

      case FUTEX_OP_LOCK_PI:
        error = atomic_cas_bool_acq (data->addr, 0, value | FUTEX_WAITERS) ?
                0 : EAGAIN;
        break;
    }

  thread_pagefault_enable ();
  return (error);
}

int
futex_wait (int *addr, int value, uint32_t flags, uint64_t ticks)
{
  CLEANUP (futex_data_fini) struct futex_data data;
  int error = futex_data_init (&data, addr, flags, FUTEX_DATA_WAIT);

  if (error)
    return (error);

  data.wait_obj = data.ops->acquire (&data.key);
  error = futex_map_addr (&data, value, FUTEX_OP_CMP);

  if (! error)
    error = data.ops->wait (&data, value, flags, ticks);

  return (error);
}

int
futex_wake (int *addr, uint32_t flags, int value)
{
  CLEANUP (futex_data_fini) struct futex_data data;
  int error = futex_data_init (&data, addr, flags, FUTEX_DATA_WAKE);

  if (error)
    return (error);

  data.wait_obj = data.ops->acquire (&data.key);

  if (flags & FUTEX_MUTATE)
    {
      error = futex_map_addr (&data, value, FUTEX_OP_SET);
      if (error)
        return (error);
    }

  if (data.wait_obj)
    error = data.ops->wake (data.wait_obj, flags);

  return (0);
}

int
futex_requeue (int *dst_addr, int *src_addr, int wake_one, uint32_t flags)
{
  if (flags & FUTEX_PI)
    return (EINVAL);

  int error = futex_check_addr (dst_addr);
  if (error)
    return (error);

  error = futex_check_addr (src_addr);
  if (error)
    return (error);

  union sync_key dkey, skey;
  struct vm_map *map = vm_map_self ();

  error = futex_key_init (&dkey, map, dst_addr, flags);
  if (error)
    return (error);

  error = futex_key_init (&skey, map, src_addr, flags);
  if (error)
    {
      if (flags & FUTEX_SHARED)
        vm_object_unref (dkey.shared.object);

      return (error);
    }

  sleepq_move (&dkey, &skey, wake_one, (flags & FUTEX_BROADCAST));

  if (flags & FUTEX_SHARED)
    {
      vm_object_unref (dkey.shared.object);
      vm_object_unref (skey.shared.object);
    }

  return (0);
}

static int
futex_robust_list_handle (struct futex_robust_list *list,
                          int *addr, int tid)
{
  CLEANUP (futex_data_fini) struct futex_data data;
  int error = futex_data_init (&data, addr, list->flags, FUTEX_DATA_WAKE);

  if (error)
    return (error);

  data.wait_obj = data.ops->acquire (&data.key);
  error = futex_map_addr (&data, tid, FUTEX_OP_ROBUST_CLEAR);
  if (error < 0)
    { // There are waiters on this robust futex. Wake them all.
      if (data.wait_obj)
        data.ops->wake (data.wait_obj, list->flags | FUTEX_BROADCAST);
      error = 0;
    }

  return (error);
}

void
futex_td_exit (struct futex_td *td)
{
  int tid = thread_id (thread_self ());
  struct futex_td rtd;

  if (!td || user_copy_from (&rtd, td, sizeof (rtd)) != 0)
    return;

  if (rtd.pending)
    futex_robust_list_handle (rtd.pending, (int *)rtd.pending, tid);

  uint32_t nmax = 1024;   // Handle this many robust futexes.
  while (rtd.list)
    {
      struct futex_robust_list tmp;
      if (user_copy_from (&tmp, rtd.list, sizeof (tmp)) != 0 ||
          futex_robust_list_handle (&tmp, (int *)rtd.list, tid) != 0 ||
          --nmax == 0)
        break;

      rtd.list = (void *)(uintptr_t)tmp.next;
    }
}
