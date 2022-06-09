/*
 * Copyright (c) 2010-2019 Richard Braun.
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

#include <stdio.h>

#include <kern/console.h>
#include <kern/fmt.h>
#include <kern/init.h>
#include <kern/spinlock.h>
#include <machine/boot.h>
#include <machine/cpu.h>

int
printf (const char *format, ...)
{
  va_list ap;
  va_start (ap, format);

  int length = vprintf (format, ap);
  va_end (ap);
  return (length);
}

int
vprintf (const char *format, va_list ap)
{
  return (fmt_vxprintf (console_stream, format, ap));
}

static int __init
printf_setup (void)
{
  return (0);
}

INIT_OP_DEFINE (printf_setup,
                INIT_OP_DEP (boot_bootstrap_console, true),
                INIT_OP_DEP (console_bootstrap, true),
                INIT_OP_DEP (spinlock_setup, true));
