/*
 * Copyright (c) 2017 Richard Braun.
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

#ifndef VM_OBJECT_TYPES_H
#define VM_OBJECT_TYPES_H

#include <stdint.h>

#include <kern/mutex.h>
#include <kern/rdxtree.h>

struct vm_object
{
  struct mutex lock;
  struct rdxtree pages;
  uint64_t size;
  size_t nr_pages;
};

#endif /* VM_OBJECT_TYPES_H */
