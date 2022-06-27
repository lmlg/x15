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

#ifndef KERN_ADAPTIVE_LOCK_I_H
#define KERN_ADAPTIVE_LOCK_I_H

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>

#include <kern/atomic.h>
#include <kern/init.h>
#include <kern/macros.h>
#include <kern/thread.h>

struct adaptive_lock
{
  uintptr_t owner;
};

/*
 * Adaptive lock flags.
 *
 * The "contended" flag indicates that threads are waiting for the lock
 * to be released, potentially spinning on the owner. It forces threads
 * trying to acquire the lock as well as the owner to take the slow path.
 */
#define ADAPTIVE_LOCK_CONTENDED   0x1UL

static inline void
adaptive_lock_init (struct adaptive_lock *lock)
{
  lock->owner = 0;
}

static inline int
adaptive_lock_tryacq (struct adaptive_lock *lock)
{
  uintptr_t owner = atomic_cas_acq (&lock->owner, 0,
                                    (uintptr_t)thread_self ());
  return (owner ? EBUSY : 0);
}

#define adaptive_lock_acquire_fast   adaptive_lock_tryacq

static inline int
adaptive_lock_release_fast (struct adaptive_lock *lock)
{
  uintptr_t prev = atomic_cas_rel (&lock->owner, (uintptr_t)thread_self (), 0);
  return ((prev & ADAPTIVE_LOCK_CONTENDED) ? EBUSY : 0);
}

void adaptive_lock_acquire_slow (struct adaptive_lock *lock);
void adaptive_lock_release_slow (struct adaptive_lock *lock);

static inline void
adaptive_lock_acquire (struct adaptive_lock *lock)
{
  if (unlikely (adaptive_lock_acquire_fast (lock) != 0))
    adaptive_lock_acquire_slow (lock);
}

static inline void
adaptive_lock_release (struct adaptive_lock *lock)
{
  if (unlikely (adaptive_lock_release_fast (lock) != 0))
    adaptive_lock_release_slow (lock);
}

// Adaptive lock guards.

static inline void
adaptive_lock_guard_fini (struct adaptive_lock **ptr)
{
  adaptive_lock_release (*ptr);
}

#define ADAPTIVE_LOCK_GUARD(lock)   \
  CLEANUP (adaptive_lock_guard_fini) __unused _Auto UNIQ(alg) =   \
    ({   \
       struct adaptive_lock *lock_ = (lock);   \
       adaptive_lock_acquire (lock_);   \
       lock_;   \
     })

#endif
