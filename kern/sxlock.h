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
};

#define SXLOCK_MASK   (0x7fffffffu)

static inline void
sxlock_init (struct sxlock *sxp)
{
  sxp->lock = 0;
}

static inline int
sxlock_tryexlock (struct sxlock *sxp)
{
  uint32_t val = atomic_load_rlx (&sxp->lock) & SXLOCK_MASK;
  return (!val && atomic_cas_bool_acq (&sxp->lock, val, val | SXLOCK_MASK) ?
          0 : EBUSY);
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
  uint32_t val = atomic_load_rlx (&sxp->lock) & SXLOCK_MASK;
  return (val != SXLOCK_MASK &&
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

void sxlock_unlock_slow (struct sxlock *sxp);

static inline void
sxlock_unlock (struct sxlock *sxp)
{
  uint32_t val = atomic_load_rlx (&sxp->lock);
  int wake;

  if ((val & SXLOCK_MASK) == SXLOCK_MASK)
    { // Exclusive lock.
      atomic_swap_rel (&sxp->lock, 0);
      wake = 1;
    }
  else
    // Shared lock. Check that the count went to 0.
    wake = (atomic_sub_rel (&sxp->lock, 1) << 1) == 2;

  if (wake && (val & (SXLOCK_MASK + 1)))
    sxlock_unlock_slow (sxp);
}

// Mutate an exclusive lock into a shared one.
static inline void
sxlock_share (struct sxlock *sxp)
{
  uint32_t prev = atomic_and (&sxp->lock, SXLOCK_MASK + 2, ATOMIC_ACQUIRE);
  if (prev & (SXLOCK_MASK + 1))
    sxlock_unlock_slow (sxp);
}

// Shared-Exclusive lock guards.

static inline void
sxlock_guard_fini (void *ptr)
{
  sxlock_unlock (*(struct sxlock **)ptr);
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
