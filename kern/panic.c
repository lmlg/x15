/*
 * Copyright (c) 2010-2014 Richard Braun.
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

#include <stdarg.h>
#include <stdio.h>

#include <kern/atomic.h>
#include <kern/panic.h>
#include <kern/unwind.h>

#include <machine/cpu.h>

static int panic_done;

void
panic (const char *format, ...)
{
  int already_done = atomic_swap (&panic_done, 1, ATOMIC_SEQ_CST);

  if (already_done)
    while (1)
      cpu_idle ();

  cpu_intr_disable ();
  cpu_halt_broadcast ();

  va_list list;
  printf ("\npanic: ");
  va_start (list, format);
  vprintf (format, list);
  printf ("\n");
  unw_backtrace (NULL);

  cpu_halt ();
  __builtin_unreachable ();
}
