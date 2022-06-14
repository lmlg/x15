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
  uint32_t val;
};

#define SXLOCK_UNOWNED    0
#define SXLOCK_SHOWNED    1
#define SXLOCK_EXOWNED    2
#define SXLOCK_EXWAITER   3

#define SXLOCK_SHIFT    2
#define SXLOCK_SHUSER   (1u << SXLOCK_SHIFT)

static inline void
sxlock_init (struct sxlock *sxp)
{
  sxp->val = 0;
}

static inline int
sxlock_tryexlock (struct sxlock *sxp)
{
  return (atomic_cas_bool_acq (&sxp->val, 0, SXLOCK_EXOWNED) ?
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
  uint32_t val = atomic_load_rlx (&sxp->val) & ~SXLOCK_EXOWNED;
  return (atomic_cas_bool_acq (&sxp->val, val,
                               (val | SXLOCK_SHOWNED) + SXLOCK_SHUSER) ?
          0 : EBUSY);
}

void sxlock_shlock_slow (struct sxlock *sxp);

static inline void
sxlock_shlock (struct sxlock *sxp)
{
  if (unlikely (sxlock_tryshlock (sxp) != 0))
    sxlock_shlock_slow (sxp);
}

void sxlock_exunlock (struct sxlock *sxp);
void sxlock_shunlock (struct sxlock *sxp);

static inline void
sxlock_unlock (struct sxlock *sxp)
{
  uint32_t val = atomic_load_rlx (&sxp->val);
  assert (val != 0);
  assert ((val & (SXLOCK_EXOWNED | SXLOCK_SHOWNED)) !=
                 (SXLOCK_EXOWNED | SXLOCK_SHOWNED));

  if (val & SXLOCK_EXOWNED)
    {
      if (atomic_cas_bool_rel (&sxp->val, SXLOCK_EXOWNED, 0))
        return;

      sxlock_exunlock (sxp);
    }
  else
    {
      if ((val >> SXLOCK_SHIFT) > 1 &&
          atomic_cas_bool_rel (&sxp->val, val, val - SXLOCK_SHUSER))
        return;

      sxlock_shunlock (sxp);
    }
}

// Shared-Exclusive guards.

static inline void
sxlock_guard_fini (void *ptr)
{
  sxlock_unlock (*(struct sxlock **)ptr);
}

#define SXLOCK_SHGUARD(sxp)   \
  CLEANUP (sxlock_guard_fini) __unused void *UNIQ(sxg) =   \
    ({   \
       struct sxlock *sxp_ = (sxp);   \
       sxlock_shlock (sxp_);   \
       sxp_;   \
     })

#define SXLOCK_EXGUARD(sxp)   \
  CLEANUP (sxlock_guard_fini) __unused void *UNIQ(sxg) =   \
    ({   \
       struct sxlock *sxp_ = (sxp);   \
       sxlock_exlock (sxp_);   \
       sxp_;   \
     })

#endif
