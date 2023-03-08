/*
 * Copyright (c) 2017 Agustina Arzille.
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
 */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <kern/adaptive_lock.h>
#include <kern/atomic.h>
#include <kern/clock.h>
#include <kern/init.h>
#include <kern/sleepq.h>
#include <kern/syscnt.h>
#include <kern/thread.h>
#include <machine/cpu.h>

static struct thread*
adaptive_lock_get_thread (uintptr_t owner)
{
  return ((struct thread *)(owner & ~ADAPTIVE_LOCK_CONTENDED));
}

static void
adaptive_lock_set_contended (struct adaptive_lock *lock)
{
  atomic_or_rel (&lock->owner, ADAPTIVE_LOCK_CONTENDED);
}

static inline bool
adaptive_lock_is_owner (struct adaptive_lock *lock, struct thread *thread)
{
  uintptr_t prev = atomic_load_rlx (&lock->owner);
  return (adaptive_lock_get_thread (prev) == thread);
}

void
adaptive_lock_acquire_slow (struct adaptive_lock *lock)
{
  uintptr_t self = (uintptr_t) thread_self ();
  struct sleepq *sleepq = sleepq_lend (lock, false);

  adaptive_lock_set_contended (lock);

  while (1)
    {
      uintptr_t owner = atomic_cas_acq (&lock->owner, ADAPTIVE_LOCK_CONTENDED,
                                        self | ADAPTIVE_LOCK_CONTENDED);

      assert (owner & ADAPTIVE_LOCK_CONTENDED);
      _Auto thr = adaptive_lock_get_thread (owner);
      if (! thr)
        break;

      /*
       * The owner may not return from the unlock function if a thread is
       * spinning on it.
       */
      while (adaptive_lock_is_owner (lock, thr))
        {
          if (thread_is_running (thr) &&
              !sleepq_test_circular (sleepq, thread_wchan_addr (thr)))
            cpu_pause ();
          else
            sleepq_wait (sleepq, "adptlk");
        }
    }

  /*
   * Attempt to clear the contended bit.
   *
   * In case of success, the current thread becomes the new owner, and
   * simply checking if the sleep queue is empty is enough.
   *
   * Keep in mind accesses to the lock word aren't synchronized by
   * the sleep queue, i.e. an unlock may occur completely concurrently
   * while attempting to clear the contended bit .
   */

  if (sleepq_empty (sleepq))
    atomic_store_rlx (&lock->owner, self);

  sleepq_return (sleepq);
}

void
adaptive_lock_release_slow (struct adaptive_lock *lock)
{
  uintptr_t self = (uintptr_t) thread_self () | ADAPTIVE_LOCK_CONTENDED;

  while (1)
    {
      uintptr_t owner = atomic_cas_rel (&lock->owner, self,
                                        ADAPTIVE_LOCK_CONTENDED);
      if (owner == self)
        break;
      
      /*
       * The contended bit was cleared after the fast path failed,
       * but before the slow path (re)started.
       */
      assert (owner == (uintptr_t) thread_self ());
      if (adaptive_lock_release_fast (lock) != 0)
        continue;

      return;
    }

  while (1)
    {
      uintptr_t owner = atomic_load_rlx (&lock->owner);

      /*
       * This only happens if :
       *  1/ Another thread was able to become the new owner, in which
       *     case that thread isn't spinning on the current thread, i.e.
       *     there is no need for an additional reference.
       *  2/ A timeout cleared the contended bit.
       */
      if (owner != ADAPTIVE_LOCK_CONTENDED)
        break;

      /*
       * Avoid contending with incoming threads that are about to spin/wait
       * on the lock. This is particularly expensive with queued locks.
       *
       * Also, this call returns NULL if another thread is currently spinning
       * on the current thread, in which case the latter doesn't return,
       * averting the need for an additional reference.
       */
      struct sleepq *sleepq = sleepq_tryacquire (lock, false);
      if (sleepq)
        {
          sleepq_signal (sleepq);
          sleepq_release (sleepq);
          break;
        }

      /*
       * Acquiring the sleep queue may fail because of contention on
       * unrelated objects. Retry.
       */
    }
}
