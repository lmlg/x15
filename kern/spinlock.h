/*
 * Copyright (c) 2012-2018 Richard Braun.
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
 * Spin locks.
 *
 * Critical sections built with spin locks run with preemption disabled.
 *
 * This module provides fair spin locks which guarantee time-bounded lock
 * acquisition depending only on the number of contending processors.
 */

#ifndef KERN_SPINLOCK_H
#define KERN_SPINLOCK_H

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>

#include <kern/atomic.h>
#include <kern/init.h>
#include <kern/macros.h>
#include <kern/spinlock_types.h>
#include <kern/thread.h>

#include <machine/cpu.h>

/*
 * Uncontended lock values.
 *
 * Any other value implies a contended lock.
 */
#define SPINLOCK_UNLOCKED   0x0
#define SPINLOCK_LOCKED     0x1

#ifdef SPINLOCK_TRACK_OWNER

static inline void
spinlock_own (struct spinlock *lock)
{
  assert (!lock->owner);
  lock->owner = thread_self ();
}

static inline void
spinlock_disown (struct spinlock *lock)
{
  assert (lock->owner == thread_self ());
  lock->owner = NULL;
}

#else
  #define spinlock_own(lock)
  #define spinlock_disown(lock)
#endif

static inline int
spinlock_lock_fast (struct spinlock *lock)
{
  uint32_t prev = atomic_cas_acq (&lock->value, SPINLOCK_UNLOCKED,
                                  SPINLOCK_LOCKED);

  if (unlikely (prev != SPINLOCK_UNLOCKED))
    return (EBUSY);

  spinlock_own (lock);
  return (0);
}

void spinlock_lock_slow (struct spinlock *lock);

static inline void
spinlock_lock_common (struct spinlock *lock)
{
  int error = spinlock_lock_fast (lock);
  if (unlikely (error))
    spinlock_lock_slow (lock);
}

static inline void
spinlock_unlock_common (struct spinlock *lock)
{
  spinlock_disown (lock);
  atomic_and_rel (&lock->value, ~SPINLOCK_LOCKED);
}

static inline bool
spinlock_locked (const struct spinlock *lock)
{
  return (atomic_load_rlx (&lock->value) != SPINLOCK_UNLOCKED);
}

#ifdef SPINLOCK_TRACK_OWNER

static inline void
spinlock_transfer_owner (struct spinlock *lock, struct thread *owner)
{
  assert (lock->owner == thread_self ());
  lock->owner = owner;
}

#else
  #define spinlock_transfer_owner(lock, owner)
#endif

// Initialize a spin lock.
void spinlock_init (struct spinlock *lock);

/*
 * Attempt to lock the given spin lock.
 *
 * Return 0 on success, EBUSY if the spin lock is already locked.
 *
 * Preemption is disabled on success.
 */
static inline int
spinlock_trylock (struct spinlock *lock)
{
  thread_preempt_disable ();
  int error = spinlock_lock_fast (lock);

  if (unlikely (error))
    thread_preempt_enable ();

  return (error);
}

/*
 * Lock a spin lock.
 *
 * If the spin lock is already locked, the calling thread spins until the
 * spin lock is unlocked.
 *
 * A spin lock can only be locked once.
 *
 * This function disables preemption.
 */
static inline void
spinlock_lock (struct spinlock *lock)
{
  thread_preempt_disable ();
  spinlock_lock_common (lock);
}

/*
 * Unlock a spin lock.
 *
 * The spin lock must be locked, and must have been locked on the same
 * processor it is unlocked on.
 *
 * This function may reenable preemption.
 */
static inline void
spinlock_unlock (struct spinlock *lock)
{
  spinlock_unlock_common (lock);
  thread_preempt_enable ();
}

/*
 * Versions of the spinlock functions that also disable interrupts during
 * critical sections.
 */

/*
 * Attempt to lock the given spin lock.
 *
 * Return 0 on success, EBUSY if the spin lock is already locked.
 *
 * Preemption and interrupts are disabled on success, in which case the
 * flags passed by the caller are filled with the previous value of the
 * CPU flags.
 */
static inline int
spinlock_trylock_intr_save (struct spinlock *lock, cpu_flags_t *flags)
{
  thread_preempt_disable_intr_save (flags);
  int error = spinlock_lock_fast (lock);

  if (unlikely (error))
    thread_preempt_enable_intr_restore (*flags);

  return (error);
}

/*
 * Lock a spin lock.
 *
 * If the spin lock is already locked, the calling thread spins until the
 * spin lock is unlocked.
 *
 * A spin lock can only be locked once.
 *
 * This function disables preemption and interrupts. The flags passed by
 * the caller are filled with the previous value of the CPU flags.
 */
static inline void
spinlock_lock_intr_save (struct spinlock *lock, cpu_flags_t *flags)
{
  thread_preempt_disable_intr_save (flags);
  spinlock_lock_common (lock);
}

/*
 * Unlock a spin lock.
 *
 * The spin lock must be locked, and must have been locked on the same
 * processor it is unlocked on.
 *
 * This function may reenable preemption and interrupts, using the given
 * flags which must have been obtained with a lock or trylock operation.
 */
static inline void
spinlock_unlock_intr_restore (struct spinlock *lock, cpu_flags_t flags)
{
  spinlock_unlock_common (lock);
  thread_preempt_enable_intr_restore (flags);
}

// Spinlock guards.

struct spinlock_guard
{
  struct spinlock *spinlock;
  cpu_flags_t flags;
  bool saved_flags;
};

static inline void
spinlock_guard_lock (struct spinlock_guard *guard)
{
  if (guard->saved_flags)
    spinlock_lock_intr_save (guard->spinlock, &guard->flags);
  else
    spinlock_lock (guard->spinlock);
}

static inline struct spinlock_guard
spinlock_guard_make (struct spinlock *spinlock, bool save_flags)
{
  struct spinlock_guard ret = { .spinlock = spinlock };
  ret.saved_flags = save_flags;
  spinlock_guard_lock (&ret);
  return (ret);
}

static inline void
spinlock_guard_fini (void *ptr)
{
  struct spinlock_guard *guard = ptr;

  if (guard->saved_flags)
    spinlock_unlock_intr_restore (guard->spinlock, guard->flags);
  else
    spinlock_unlock (guard->spinlock);
}

#define SPINLOCK_GUARD_MAKE(spinlock, save_flags)   \
  CLEANUP (spinlock_guard_fini) _Auto __unused UNIQ (sg) =   \
    spinlock_guard_make ((spinlock), (save_flags))

#define SPINLOCK_INTR_GUARD(spinlock)   SPINLOCK_GUARD_MAKE ((spinlock), true)

#define SPINLOCK_GUARD(spinlock)   SPINLOCK_GUARD_MAKE ((spinlock), false)

/*
 * This init operation provides :
 *  - uncontended spinlock locking
 *
 * Contended locking may only occur after starting APs.
 */
INIT_OP_DECLARE (spinlock_setup);

#endif
