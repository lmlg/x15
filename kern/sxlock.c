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

void
sxlock_exlock_slow (struct sxlock *sxp)
{
  sxlock_lock_impl (sxlock_tryexlock, "sxlock/X", sxp);
}

void
sxlock_shlock_slow (struct sxlock *sxp)
{
  sxlock_lock_impl (sxlock_tryshlock, "sxlock/S", sxp);
}

void
sxlock_unlock (struct sxlock *sxp)
{
  while (1)
    {
      uint32_t val = atomic_load_rlx (&sxp->lock);
      if (val == (SXLOCK_WAITERS | SXLOCK_MASK) ||
          val == (SXLOCK_WAITERS | 1))
        break;

      uint32_t nval = val == SXLOCK_MASK ? 0 : val - 1;
      if (atomic_cas_bool_rel (&sxp->lock, val, nval))
        return;

      cpu_pause ();
    }

  _Auto sleepq = sleepq_acquire (sxp);
  uint32_t val = atomic_load_rlx (&sxp->lock);
  int wake;

  if ((val & SXLOCK_MASK) == SXLOCK_MASK)
    {
      atomic_swap_rel (&sxp->lock, 0);
      wake = 1;
    }
  else
    {
      uint32_t prev = atomic_sub_rel (&sxp->lock, 1);
      wake = (int)((prev >> SXLOCK_WAITERS_BIT) & (prev & 1));
    }

  if (! sleepq)
    return;
  else if (wake)
    sleepq_broadcast (sleepq);

  sleepq_release (sleepq);
}

void
sxlock_share_slow (struct sxlock *sxp)
{
  struct sleepq *sleepq = sleepq_acquire (sxp);
  if (sleepq)
    {
      sleepq_broadcast (sleepq);
      sleepq_release (sleepq);
    }
}
