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
 * Shared-Exclusive locks.
 */

#ifndef KERN_SXLOCK_H
#define KERN_SXLOCK_H   1

#include <stdint.h>

#include <kern/atomic.h>
#include <kern/list.h>
#include <kern/spinlock.h>

struct sxlock
{
  uint32_t word;
  struct spinlock lock;
  struct list waiters;
  struct list readers;
};

#define SXLOCK_WAITERS_BIT   31
#define SXLOCK_WAITERS       (1u << SXLOCK_WAITERS_BIT)
#define SXLOCK_MASK          (SXLOCK_WAITERS - 1)

/*
 * Possible values for the Shared-Exclusive word:
 *
 * 0 => Unlocked, can be taken by readers or writers.
 * INT32_MAX => Locked by a writer.
 * N where N in [1 .. INT32_MAX) => Locked by N readers.
 *
 * The presence of the SXLOCK_WAITERS bit indicates that there is
 * contention and that upon unlocking, the next owner will be determined
 * by the waiters' priorities (A process called 'phasing'). This is
 * indicated by setting the word to just SXLOCK_WAITERS, which forces waiters
 * to take the (potentially) slow path.
 *
 * Note that setting and clearing the SXLOCK_WAITERS bit must done by
 * acquiring the internal spinlock.
 */

static inline void
sxlock_init (struct sxlock *sxp)
{
  sxp->word = 0;
  spinlock_init (&sxp->lock);
  list_init (&sxp->readers);
  list_init (&sxp->waiters);
}

static inline bool
sxlock_exclusive (uint32_t value)
{
  return ((value & SXLOCK_MASK) == SXLOCK_MASK);
}

static inline bool
sxlock_phasing (uint32_t value)
{
  return (value == SXLOCK_WAITERS);
}

static inline int
sxlock_tryexlock (struct sxlock *sxp)
{
  return (atomic_cas_bool_acq (&sxp->word, 0, SXLOCK_MASK) ? 0 : EBUSY);
}

void sxlock_exlock_slow (struct sxlock *sxp);

static inline void
sxlock_exlock (struct sxlock *sxp)
{
  if (sxlock_tryexlock (sxp) != 0)
    sxlock_exlock_slow (sxp);
}

static inline int
sxlock_tryshlock (struct sxlock *sxp)
{
  uint32_t val = atomic_load_rlx (&sxp->word);
  return (!sxlock_exclusive (val) &&
          !sxlock_phasing (val) &&
          atomic_cas_bool_acq (&sxp->word, val, val + 1) ? 0 : EBUSY);
}

void sxlock_shlock_slow (struct sxlock *sxp);

static inline void
sxlock_shlock (struct sxlock *sxp)
{
  if (sxlock_tryshlock (sxp) != 0)
    sxlock_shlock_slow (sxp);
}

void sxlock_wake_readers (struct sxlock *sxp);

// Mutate an exclusive lock into a shared one.
static inline void
sxlock_share (struct sxlock *sxp)
{
  uint32_t prev = atomic_and_rel (&sxp->word, SXLOCK_WAITERS | 1);
  if (prev & SXLOCK_WAITERS)
    {
      SPINLOCK_GUARD (&sxp->lock);
      sxlock_wake_readers (sxp);
    }
}

void sxlock_unlock_slow (struct sxlock *sxp);

static inline void
sxlock_unlock (struct sxlock *sxp)
{
  uint32_t tmp = atomic_load_rlx (&sxp->word);
  tmp = sxlock_exclusive (tmp) ?
        (atomic_and_rel (&sxp->word, SXLOCK_WAITERS) & SXLOCK_WAITERS) :
        atomic_sub_rel (&sxp->word, 1) - 1;

  if (sxlock_phasing (tmp))
    sxlock_unlock_slow (sxp);
}

// Shared-Exclusive lock guards.

static inline void
sxlock_guard_fini (void *ptr)
{
  sxlock_unlock (*(struct sxlock **)ptr);
}

#define SXLOCK_GUARD_IMPL(sxp, fn)   \
  CLEANUP (sxlock_guard_fini) __unused _Auto UNIQ(sxg) =   \
    ({   \
       struct sxlock *sxp_ = (sxp);   \
       fn (sxp_);   \
       sxp_;   \
     })

#define SXLOCK_SHGUARD(sxp)   SXLOCK_GUARD_IMPL (sxp, sxlock_shlock)
#define SXLOCK_EXGUARD(sxp)   SXLOCK_GUARD_IMPL (sxp, sxlock_exlock)

#endif
