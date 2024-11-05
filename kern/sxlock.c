/*
 * Copyright (c) 2022 Agustina Arzille.
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

#include <kern/sxlock.h>
#include <kern/thread.h>

/*
 * Waiters are queued in FIFO order, but readers have their own separate
 * lists so that a call to 'sxlock_share' can be made atomic.
 */

struct sxlock_waiter
{
  struct list node;
  struct list rdnode;
  struct thread *thread;
  bool woken;
};

static void
sxlock_waiter_init (struct sxlock_waiter *wp)
{
  wp->thread = thread_self ();
  wp->woken = false;
}

static void
sxlock_waiter_wake (struct sxlock_waiter *wp)
{
  wp->woken = true;
  thread_wakeup (wp->thread);
}

static inline bool
sxlock_exmark (struct sxlock *sxp)
{
  /*
   * Try to mark the lock as having waiters, or acquire it if it's been
   * released in the meantime.
   */
  while (1)
    {
      uint32_t tmp = atomic_load_rlx (&sxp->word);
      if (! tmp)
        {
          if (atomic_cas_bool_acq (&sxp->word, tmp,
                                   SXLOCK_MASK | SXLOCK_WAITERS))
            return (false);
        }
      else if ((tmp & SXLOCK_WAITERS) ||
               atomic_cas_bool_acq (&sxp->word, tmp, tmp | SXLOCK_WAITERS))
        return (true);

      atomic_spin_nop ();
    }
}

void
sxlock_exlock_slow (struct sxlock *sxp)
{
  struct sxlock_waiter w;
  sxlock_waiter_init (&w);

  SPINLOCK_GUARD (&sxp->lock);
  list_insert_tail (&sxp->waiters, &w.node);

  if (sxlock_exmark (sxp))
    {
      while (!w.woken)
        thread_sleep (&sxp->lock, sxp, "sxlock/X");

      atomic_store_rel (&sxp->word, SXLOCK_MASK | SXLOCK_WAITERS);
    }

  list_remove (&w.node);
}

static inline int
sxlock_shmark (struct sxlock *sxp)
{
  while (1)
    {
      uint32_t tmp = atomic_load_rlx (&sxp->word);
      if (!sxlock_exclusive (tmp) && !sxlock_phasing (tmp))
        {
          if (atomic_cas_bool_acq (&sxp->word, tmp,
                                   (tmp + 1) | SXLOCK_WAITERS))
            return (false);
        }
      else if ((tmp & SXLOCK_WAITERS) ||
               atomic_cas_bool_acq (&sxp->word, tmp, tmp | SXLOCK_WAITERS))
        return (true);

      atomic_spin_nop ();
    }
}

void
sxlock_shlock_slow (struct sxlock *sxp)
{
  struct sxlock_waiter w;
  sxlock_waiter_init (&w);

  SPINLOCK_GUARD (&sxp->lock);
  list_insert_tail (&sxp->waiters, &w.node);
  list_insert_tail (&sxp->readers, &w.rdnode);

  if (sxlock_shmark (sxp))
    {
      while (!w.woken)
        thread_sleep (&sxp->lock, sxp, "sxlock/S");

      atomic_add_rel (&sxp->word, 1);
    }

  list_remove (&w.node);
  list_remove (&w.rdnode);
  // Readers also wake up their peers.
  sxlock_wake_readers (sxp);
}

void
sxlock_unlock_slow (struct sxlock *sxp)
{
  SPINLOCK_GUARD (&sxp->lock);
  if (list_empty (&sxp->waiters))
    { // No more waiters - Clear the contended bit.
      atomic_store_rel (&sxp->word, 0);
      return;
    }

  _Auto first = list_first_entry (&sxp->waiters, struct sxlock_waiter, node);
  assert (first);
  sxlock_waiter_wake (first);
}

void
sxlock_wake_readers (struct sxlock *sxp)
{
  if (list_empty (&sxp->readers))
    return;

  _Auto next = list_first_entry (&sxp->readers, struct sxlock_waiter, rdnode);
  sxlock_waiter_wake (next);
}
