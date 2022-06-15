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

void
sxlock_exlock_slow (struct sxlock *sxp)
{
  struct sleepq *sleepq = sleepq_lend (sxp, true);
  atomic_or_rlx (&sxp->val, SXLOCK_EXWAITER);

  while (1)
    {
      if (sxlock_tryexlock (sxp) == 0)
        break;

      sleepq_wait (sleepq, "sxlock_ex");
    }
}

void
sxlock_shlock_slow (struct sxlock *sxp)
{
  struct sleepq *sleepq = sleepq_lend (sxp, false);

  while (1)
    {
      if (sxlock_tryshlock (sxp) == 0)
        break;

      sleepq_wait (sleepq, "sxlock_sh");
    }

  if (!sleepq_empty (sleepq))
    /* If there were any other readers waiting on the lock, 
     * wake them up now. */
    sleepq_broadcast (sleepq);
}

void
sxlock_exunlock (struct sxlock *sxp)
{
  uint32_t nval = atomic_and_rel (&sxp->val, ~SXLOCK_EXOWNED);

  if ((nval >> SXLOCK_SHIFT) > 0)
    { // Always check for readers first.
      struct sleepq *sleepq = sleepq_acquire (sxp, false);
      if (sleepq)
        {
          sleepq_broadcast (sleepq);
          sleepq_release (sleepq);
          return;
        }
    }

  if (nval & SXLOCK_EXWAITER)
    {
      struct sleepq *sleepq = sleepq_acquire (sxp, true);
      if (sleepq)
        {
          sleepq_signal (sleepq);
          sleepq_release (sleepq);
        }
    }
}

void
sxlock_shunlock (struct sxlock *sxp)
{
  while (1)
    {
      uint32_t val = atomic_load_rlx (&sxp->val);
      uint32_t nval = val - SXLOCK_SHUSER;

      if ((nval >> SXLOCK_SHIFT) == 0)
        // If we are the last reader, clear the 'shared ownership' bit.
        nval &= ~SXLOCK_SHOWNED;

      if (! atomic_cas_bool_rel (&sxp->val, val, nval))
        {
          cpu_pause ();
          continue;
        }
      else if (! nval)
        // No writers waiting on this lock.
        return;

      // We may need to wake a writer.
      struct sleepq *sleepq = sleepq_acquire (sxp, true);
      if (sleepq)
        {
          sleepq_signal (sleepq);
          sleepq_release (sleepq);
        }

      return;
    }
}
