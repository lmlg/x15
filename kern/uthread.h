/*
 * Copyright (c) 2026 Agustina Arzille.
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
 * Definitions for userspace threads.
 */

#ifndef KERN_UTHREAD_H
#define KERN_UTHREAD_H

#include <stdint.h>

#include <kern/futex.h>
#include <kern/init.h>

struct uthread
{
  struct futex_td futex_td;
  int *tid;
};

struct uthread* uthread_allocate (void);

void uthread_free (struct uthread *uthread);

void uthread_exit (struct uthread *uthread);

INIT_OP_DECLARE (uthread_setup);

#endif
