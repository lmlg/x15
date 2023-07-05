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
sxlock_unlock_slow (struct sxlock *sxp)
{
  struct sleepq *sleepq = sleepq_acquire (sxp);
  if (sleepq)
    {
      sleepq_broadcast (sleepq);
      sleepq_release (sleepq);
    }
}
