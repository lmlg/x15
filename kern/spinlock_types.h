/*
 * Copyright (c) 2017-2018 Richard Braun.
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
 * Isolated type definition used to avoid inclusion circular dependencies.
 */

#ifndef KERN_SPINLOCK_TYPES_H
#define KERN_SPINLOCK_TYPES_H

#include <stdint.h>

#ifdef CONFIG_SPINLOCK_DEBUG
  #define SPINLOCK_TRACK_OWNER
#endif

struct thread;

struct spinlock
{
  uint32_t value;

#ifdef SPINLOCK_TRACK_OWNER
  struct thread *owner;
#endif
};

#endif
