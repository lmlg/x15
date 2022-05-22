/*
 * Copyright (c) 2017 Richard Braun.
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
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <kern/atomic.h>
#include <kern/init.h>
#include <kern/mutex.h>
#include <kern/sleepq.h>
#include <kern/syscnt.h>

static int
mutex_lock_slow_common (struct mutex *mutex, bool timed, uint64_t ticks)
{
  int error = 0;
  struct sleepq *sleepq = sleepq_lend (mutex, false);

  while (1)
    {
      uint32_t state = atomic_swap_rel (&mutex->state, MUTEX_CONTENDED);

      if (state == MUTEX_UNLOCKED)
        break;
      else if (!timed)
        sleepq_wait (sleepq, "mutex");
      else
        {
          error = sleepq_timedwait (sleepq, "mutex", ticks);
          if (error)
            break;
        }
    }

  if (sleepq_empty (sleepq))
    {
      if (error)
        atomic_cas_rlx (&mutex->state, MUTEX_CONTENDED, MUTEX_LOCKED);
      else
        atomic_store_rlx (&mutex->state, MUTEX_LOCKED);
    }

  sleepq_return (sleepq);
  return (error);
}

void
mutex_lock_slow (struct mutex *mutex)
{
  int error = mutex_lock_slow_common (mutex, false, 0);
  assert (! error);
}

int
mutex_timedlock_slow (struct mutex *mutex, uint64_t ticks)
{
  return (mutex_lock_slow_common (mutex, true, ticks));
}

void
mutex_unlock_slow (struct mutex *mutex)
{
  struct sleepq *sleepq = sleepq_acquire (mutex, false);
  if (! sleepq)
    return;

  sleepq_signal (sleepq);
  sleepq_release (sleepq);
}

static int __init
mutex_bootstrap (void)
{
  return (0);
}

INIT_OP_DEFINE (mutex_bootstrap,
                INIT_OP_DEP (thread_setup_booter, true));

static int __init
mutex_setup (void)
{
  return (0);
}

INIT_OP_DEFINE (mutex_setup);
