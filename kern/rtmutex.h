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
 *
 * Real-time mutual exclusion locks.
 *
 * A real-time mutex is similar to a regular mutex, except priority
 * inheritance is unconditionally enabled.
 */

#ifndef KERN_RTMUTEX_H
#define KERN_RTMUTEX_H

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>

#include <kern/atomic.h>
#include <kern/init.h>
#include <kern/macros.h>
#include <kern/rtmutex_types.h>
#include <kern/thread.h>

/*
 * Real-time mutex flags.
 *
 * The "contended" flag indicates that threads are waiting for the mutex
 * to be unlocked. It forces threads trying to lock the mutex as well as
 * the owner to take the slow path.
 *
 * The "force-wait" flag prevents "stealing" a mutex. When a contended
 * mutex is unlocked, a thread may concurrently try to lock it. Without
 * this flag, it may succeed, and in doing so, it would prevent a
 * potentially higher priority thread from locking the mutex. The flag
 * forces all threads to not only take the slow path, but to also call
 * the turnstile wait function so that only the highest priority thread
 * may lock the mutex.
 */
#define RTMUTEX_CONTENDED    ((uintptr_t)0x1)
#define RTMUTEX_FORCE_WAIT   ((uintptr_t)0x2)

#define RTMUTEX_OWNER_MASK   \
  (~((uintptr_t)(RTMUTEX_FORCE_WAIT | RTMUTEX_CONTENDED)))

static inline bool
rtmutex_owner_aligned (uintptr_t owner)
{
  return ((owner & ~RTMUTEX_OWNER_MASK) == 0);
}

static inline uintptr_t
rtmutex_lock_fast (struct rtmutex *rtmutex)
{
  uintptr_t owner = (uintptr_t)thread_self ();
  assert (rtmutex_owner_aligned (owner));
  return (atomic_cas (&rtmutex->owner, 0, owner, ATOMIC_ACQUIRE));
}

static inline uintptr_t
rtmutex_unlock_fast (struct rtmutex *rtmutex)
{
  uintptr_t owner = (uintptr_t)thread_self ();
  assert (rtmutex_owner_aligned (owner));
  uintptr_t prev_owner = atomic_cas (&rtmutex->owner, owner, 0,
                                     ATOMIC_RELEASE);
  assert ((prev_owner & RTMUTEX_OWNER_MASK) == owner);
  return (prev_owner);
}

void rtmutex_lock_slow (struct rtmutex *rtmutex);

int rtmutex_timedlock_slow (struct rtmutex *rtmutex, uint64_t ticks);

void rtmutex_unlock_slow (struct rtmutex *rtmutex);

static inline bool
rtmutex_locked (const struct rtmutex *rtmutex)
{
  uintptr_t owner = atomic_load (&rtmutex->owner, ATOMIC_RELAXED);
  return (owner != 0);
}

// Initialize a real-time mutex.
static inline void
rtmutex_init (struct rtmutex *rtmutex)
{
  rtmutex->owner = 0;
}

/*
 * Attempt to lock the given real-time mutex.
 *
 * This function may not sleep.
 *
 * Return 0 on success, EBUSY if the mutex is already locked.
 */
static inline int
rtmutex_trylock (struct rtmutex *rtmutex)
{
  uintptr_t prev_owner = rtmutex_lock_fast (rtmutex);
  return (prev_owner ? EBUSY : 0);
}

/*
 * Lock a real-time mutex.
 *
 * If the mutex is already locked, the calling thread sleeps until the
 * mutex is unlocked, and its priority is propagated as needed to prevent
 * unbounded priority inversion.
 *
 * A mutex can only be locked once.
 *
 * This function may sleep.
 */
static inline void
rtmutex_lock (struct rtmutex *rtmutex)
{
  uintptr_t prev_owner = rtmutex_lock_fast (rtmutex);
  if (unlikely (prev_owner))
    rtmutex_lock_slow (rtmutex);
}

/*
 * Lock a real-time mutex, with a time boundary.
 *
 * The time boundary is an absolute time in ticks.
 *
 * If successful, the mutex is locked, otherwise an error is returned.
 * A mutex can only be locked once.
 *
 * This function may sleep.
 */
static inline int
rtmutex_timedlock (struct rtmutex *rtmutex, uint64_t ticks)
{
  uintptr_t prev_owner = rtmutex_lock_fast (rtmutex);
  return (prev_owner ? rtmutex_timedlock_slow (rtmutex, ticks) : 0);
}

/*
 * Unlock a real-time mutex.
 *
 * The mutex must be locked, and must have been locked by the calling
 * thread.
 */
static inline void
rtmutex_unlock (struct rtmutex *rtmutex)
{
  uintptr_t prev_owner = rtmutex_unlock_fast (rtmutex);
  if (unlikely (prev_owner & RTMUTEX_CONTENDED))
    rtmutex_unlock_slow (rtmutex);
}

// Mutex init operations. See kern/mutex.h.
INIT_OP_DECLARE (rtmutex_bootstrap);
INIT_OP_DECLARE (rtmutex_setup);

#endif
