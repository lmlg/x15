/*
 * Copyright (c) 2017-2019 Richard Braun.
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

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>

#include <kern/semaphore.h>
#include <kern/sleepq.h>

void
semaphore_init (struct semaphore *semaphore, uint16_t value, uint16_t max_value)
{
  assert (value <= max_value);
  semaphore->value = value;
  semaphore->max_value = max_value;
}

int
semaphore_trywait (struct semaphore *semaphore)
{
  cpu_flags_t flags;
  _Auto sleepq = sleepq_lend_intr_save (semaphore, &flags);
  int error;

  if (!semaphore->value)
    error = EAGAIN;
  else
    {
      --semaphore->value;
      error = 0;
    }

  sleepq_return_intr_restore (sleepq, flags);
  return (error);
}

void
semaphore_wait (struct semaphore *semaphore)
{
  cpu_flags_t flags;
  _Auto sleepq = sleepq_lend_intr_save (semaphore, &flags);

  while (1)
    {
      if (semaphore->value)
        {
          --semaphore->value;
          break;
        }

      sleepq_wait (sleepq, "sem");
    }

  sleepq_return_intr_restore (sleepq, flags);
}

int
semaphore_timedwait (struct semaphore *semaphore, uint64_t ticks)
{
  cpu_flags_t flags;
  _Auto sleepq = sleepq_lend_intr_save (semaphore, &flags);
  int error;

  while (1)
    {
      if (semaphore->value)
        {
          --semaphore->value;
          error = 0;
          break;
        }

      error = sleepq_timedwait (sleepq, "sem", ticks);

      if (error)
        break;
    }

  sleepq_return_intr_restore (sleepq, flags);
  return (error);
}

int
semaphore_post (struct semaphore *semaphore)
{
  cpu_flags_t flags;
  _Auto sleepq = sleepq_lend_intr_save (semaphore, &flags);
  int error;

  if (semaphore->value == semaphore->max_value)
    error = EOVERFLOW;
  else
    {
      assert (semaphore->value < semaphore->max_value);
      ++semaphore->value;
      sleepq_signal (sleepq);
      error = 0;
    }

  sleepq_return_intr_restore (sleepq, flags);
  return (error);
}
