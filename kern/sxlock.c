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
 */

#include <kern/sleepq.h>
#include <kern/sxlock.h>

#include <machine/cpu.h>

#define sxlock_lock_impl(try_lock, label, obj)   \
  do   \
    {   \
      struct sleepq *sleepq = sleepq_lend (obj);   \
      atomic_or_rel (&(obj)->lock, SXLOCK_WAITERS);   \
      \
      while (1)   \
        {   \
          if (try_lock (obj) == 0)   \
            break;   \
          \
          sleepq_wait (sleepq, label);   \
        }   \
      \
      sleepq_return (sleepq);   \
    }   \
  while (0)

static inline int
sxlock_exmark (struct sxlock *sxp)
{
  while (1)
    {
      uint32_t val = atomic_load_rlx (&sxp->lock);
      if (! val)
        {
          if (atomic_cas_bool_acq (&sxp->lock, 0, SXLOCK_MASK))
            return (0);
        }
      else if ((val & SXLOCK_WAITERS) ||
               atomic_cas_bool_acq (&sxp->lock, val, val | SXLOCK_WAITERS))
        return (1);

      cpu_pause ();
    }
}

void
sxlock_exlock_slow (struct sxlock *sxp)
{
  _Auto sleepq = sleepq_lend (sxp);
  while (1)
    {
      if (!sxlock_exmark (sxp))
        break;

      sleepq_wait (sleepq, "sxlock/X");
    }

  sleepq_return (sleepq);
}

static inline int
sxlock_shmark (struct sxlock *sxp)
{
  while (1)
    {
      uint32_t val = atomic_load_rlx (&sxp->lock);
      if ((val & SXLOCK_MASK) == 0)
        {
          if (atomic_cas_bool_acq (&sxp->lock, val, val + 1))
            return (0);
        }
      else if ((val & SXLOCK_WAITERS) ||
               atomic_cas_bool_acq (&sxp->lock, val, val | SXLOCK_WAITERS))
        return (1);

      cpu_pause ();
    }
}

void
sxlock_shlock_slow (struct sxlock *sxp)
{
  _Auto sleepq = sleepq_lend (sxp);
  while (1)
    {
      if (!sxlock_shmark (sxp))
        break;

      sleepq_wait (sleepq, "sxlock/S");
    }

  sleepq_return (sleepq);
}

void
sxlock_unlock (struct sxlock *sxp)
{
  uint32_t prev, last;

  while (1)
    {
      prev = atomic_load_rlx (&sxp->lock);
      last = (prev & SXLOCK_MASK) == SXLOCK_MASK ||
             prev == (SXLOCK_WAITERS | 1);

      uint32_t nval = last ? 0 : prev - 1;
      if (atomic_cas_bool_rel (&sxp->lock, prev, nval))
        break;

      cpu_pause ();
    }

  if (last && (prev & SXLOCK_WAITERS))
    sxlock_wake (sxp);
}

void
sxlock_wake (struct sxlock *sxp)
{
  struct sleepq *sleepq = sleepq_acquire (sxp);
  if (sleepq)
    {
      sleepq_broadcast (sleepq);
      sleepq_release (sleepq);
    }
}
