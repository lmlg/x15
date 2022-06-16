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

#define sxlock_lock_impl(try_lock, cond, label, obj)   \
  do   \
    {   \
      if (try_lock (obj) == 0)   \
        return;   \
      \
      uint32_t val = atomic_load_rlx (&(obj)->lock);   \
      if (cond (val))   \
        continue;   \
      \
      uint32_t tx = val | 0x80000000u;   \
      atomic_add_rlx (&(obj)->waiters, 1);   \
      atomic_cas_acq (&(obj)->lock, val, tx);   \
      \
      struct sleepq *sleepq = sleepq_lend (obj, false);   \
      sleepq_wait (sleepq, label);   \
    }   \
  while (0)

void
sxlock_exlock_slow (struct sxlock *sxp)
{
#define COND(x)   ((x) == 0)
  sxlock_lock_impl (sxlock_tryexlock, COND, "sxlock/0", sxp);
#undef COND
}

void
sxlock_shlock_slow (struct sxlock *sxp)
{
#define COND(x)   ((x) == 0 || (((x) & 0x7fffffffu) != 0x7fffffffu))
  sxlock_lock_impl (sxlock_tryshlock, COND, "sxlock/1", sxp);
#undef COND
}

void
sxlock_unlock (struct sxlock *sxp)
{
  while (1)
    {
      uint32_t val = atomic_load_rlx (&sxp->lock),
               cnt = val & 0x7fffffffu,
               waiters = atomic_load_rlx (&sxp->waiters),
               nval = (cnt == 0x7fffffffu || cnt == 1) ? 0 : val - 1;

      if (!atomic_cas_bool_rel (&sxp->lock, val, nval))
        {
          cpu_pause ();
          continue;
        }
      else if (!nval && (waiters || (val & 0x80000000u)))
        {
          struct sleepq *sleepq = sleepq_acquire (sxp, false);
          if (sleepq)
            {
              (cnt > 1 ? sleepq_broadcast : sleepq_signal) (sleepq);
              sleepq_release (sleepq);
            }
        }

      return;
    }
}
