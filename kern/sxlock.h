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

struct sxlock
{
  uint32_t lock;
  uint32_t waiters;
};

/*
 * Values for the lowest 2 bits of an sxlock.
 * Note that the combination of SXLOCK_EXOWNED | SXLOCK_SHOWNED is
 * forbidden, while all others are allowed.
 */

#define SXLOCK_UNOWNED    0   // Unowned lock.
#define SXLOCK_SHOWNED    1   // Owned by readers.
#define SXLOCK_EXOWNED    2   // Owned by a writer.
#define SXLOCK_EXWAITER   3   // A writer is waiting on the lock.

/*
 * The rest of the word contains the number of readers.
 * Whether they are waiting or own the lock is determined by the
 * above bits.
 */

#define SXLOCK_SHIFT    2
#define SXLOCK_SHUSER   (1u << SXLOCK_SHIFT)

static inline void
sxlock_init (struct sxlock *sxp)
{
  sxp->lock = 0;
  sxp->waiters = 0;
}

static inline int
sxlock_tryexlock (struct sxlock *sxp)
{
  return (atomic_cas_bool_acq (&sxp->lock, 0, 0x7fffffffu) ? 0 : EBUSY);
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
  uint32_t val = atomic_load_rlx (&sxp->lock);
  return (val != 0x7fffffffu &&
          atomic_cas_bool_acq (&sxp->lock, val, val + 1) ?
          0 : EBUSY);
}

void sxlock_shlock_slow (struct sxlock *sxp);

static inline void
sxlock_shlock (struct sxlock *sxp)
{
  if (unlikely (sxlock_tryshlock (sxp) != 0))
    sxlock_shlock_slow (sxp);
}

void sxlock_unlock (struct sxlock *sxp);

// Shared-Exclusive guards.

static inline void
sxlock_guard_fini (struct sxlock **ptr)
{
  sxlock_unlock (*ptr);
}

#define SXLOCK_SHGUARD(sxp)   \
  CLEANUP (sxlock_guard_fini) __unused _Auto UNIQ(sxg) =   \
    ({   \
       struct sxlock *sxp_ = (sxp);   \
       sxlock_shlock (sxp_);   \
       sxp_;   \
     })

#define SXLOCK_EXGUARD(sxp)   \
  CLEANUP (sxlock_guard_fini) __unused _Auto UNIQ(sxg) =   \
    ({   \
       struct sxlock *sxp_ = (sxp);   \
       sxlock_exlock (sxp_);   \
       sxp_;   \
     })

#endif
