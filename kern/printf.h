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
 *
 *
 * Formatted output functions.
 *
 * The printf() and vprintf() functions internally use a statically
 * allocated buffer. They won't produce output larger than 1 KiB. They can
 * be used safely in any context.
 *
 * See the sprintf module for information about the supported formats.
 */

#ifndef KERN_PRINTF_H
#define KERN_PRINTF_H

#ifndef STDIO_H
  #error "do not use <kern/printf.h> directly; include <stdio.h> instead"
#endif

#include <stdarg.h>

#include <kern/init.h>

int printf (const char *format, ...)
  __attribute__ ((format (printf, 1, 2)));

int vprintf (const char *format, va_list ap)
  __attribute__ ((format (printf, 1, 0)));

/*
 * This init operation provides :
 *  - printf is usable
 */
INIT_OP_DECLARE (printf_setup);

#endif
