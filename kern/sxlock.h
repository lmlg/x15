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

#define SXLOCK_WAITERS   (1u << 31)
#define SXLOCK_MASK      (SXLOCK_WAITERS - 1)

static inline void
sxlock_init (struct sxlock *sxp)
{
  sxp->lock = 0;
}

static inline int
sxlock_tryexlock (struct sxlock *sxp)
{
  uint32_t val = atomic_load_rlx (&sxp->lock);
  return ((val & SXLOCK_MASK) == 0 &&
          atomic_cas_bool_acq (&sxp->lock, val, val | SXLOCK_MASK) ? 0 : EBUSY);
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
  return ((val & SXLOCK_MASK) != SXLOCK_MASK &&
          atomic_cas_bool_acq (&sxp->lock, val, val + 1) ? 0 : EBUSY);
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
  int wake;

  if ((atomic_load_rlx (&sxp->lock) & SXLOCK_MASK) == SXLOCK_MASK)
    { // Exclusive lock.
      uint32_t prev = atomic_swap_rel (&sxp->lock, 0);
      wake = (prev & SXLOCK_WAITERS) != 0;
    }
  else
    {
      uint32_t prev = atomic_sub_rel (&sxp->lock, 1);
      wake = prev == (SXLOCK_WAITERS | 1);
    }

  if (wake)
    sxlock_unlock_slow (sxp);
}

// Mutate an exclusive lock into a shared one.
static inline void
sxlock_share (struct sxlock *sxp)
{
  uint32_t prev = atomic_and (&sxp->lock, SXLOCK_WAITERS | 1, ATOMIC_ACQUIRE);
  if (prev & SXLOCK_WAITERS)
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
