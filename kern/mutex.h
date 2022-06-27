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
 *
 * Mutual-exclusion locks.
 */

#ifndef KERN_MUTEX_H
#define KERN_MUTEX_H

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>

#include <kern/atomic.h>
#include <kern/init.h>
#include <kern/macros.h>

#define MUTEX_UNLOCKED    0
#define MUTEX_LOCKED      1
#define MUTEX_CONTENDED   2

struct mutex
{
  uint32_t state;
};

static inline void
mutex_init (struct mutex *mutex)
{
  mutex->state = MUTEX_UNLOCKED;
}

static inline bool
mutex_locked (const struct mutex *mutex)
{
  return (atomic_load_rlx (&mutex->state) != MUTEX_UNLOCKED);
}

static inline int
mutex_trylock (struct mutex *mutex)
{
  uint32_t state = atomic_cas_acq (&mutex->state,
                                   MUTEX_UNLOCKED, MUTEX_LOCKED);
  return (state != MUTEX_UNLOCKED ? EBUSY : 0);
}

static inline int
mutex_unlock_fast (struct mutex *mutex)
{
  uint32_t state = atomic_swap_rel (&mutex->state, MUTEX_UNLOCKED);
  return (state == MUTEX_CONTENDED ? EBUSY : 0);
}

void mutex_lock_slow (struct mutex *mutex);
int mutex_timedlock_slow (struct mutex *mutex, uint64_t ticks);
void mutex_unlock_slow (struct mutex *mutex);

static inline void
mutex_lock (struct mutex *mutex)
{
  if (unlikely (mutex_trylock (mutex) != 0))
    mutex_lock_slow (mutex);
}

static inline int
mutex_timedlock (struct mutex *mutex, uint64_t ticks)
{
  if (likely (mutex_trylock (mutex) == 0))
    return (0);
  return (mutex_timedlock_slow (mutex, ticks));
}

static inline void
mutex_unlock (struct mutex *mutex)
{
  if (unlikely (mutex_unlock_fast (mutex) != 0))
    mutex_unlock_slow (mutex);
}

// Mutex guards.

static inline void
mutex_guard_fini (struct mutex **ptr)
{
  mutex_unlock (*ptr);
}

#define MUTEX_GUARD(mtx)   \
  CLEANUP (mutex_guard_fini) __unused _Auto UNIQ(mg) =   \
  ({   \
    struct mutex *mutex_ = (mtx);   \
    mutex_lock (mutex_);   \
    mutex_;   \
  })

/*
 * Special init operation for syscnt_setup.
 *
 * This init operation only exists to avoid a circular dependency between
 * syscnt_setup and mutex_setup, without giving syscnt_setup knowledge
 * about the dependencies of mutex_setup.
 */
INIT_OP_DECLARE (mutex_bootstrap);

/*
 * This init operation provides :
 *  - uncontended mutex locking
 *
 * Contended locking may only occur after starting the scheduler.
 */
INIT_OP_DECLARE (mutex_setup);

#endif
