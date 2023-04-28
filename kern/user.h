/*
 * Copyright (c) 2023 Agustina Arzille.
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
 * Definitions for userspace.
 */

#ifndef KERN_USER_H
#define KERN_USER_H

#include <stdbool.h>
#include <stdint.h>

#include <machine/pmap.h>

#include <kern/task.h>

struct iovec;

// Test that an address is accessible for the current task.
static inline bool
user_check_addr (const void *addr)
{
  return (
#if PMAP_START_ADDRESS > 0
           ((uintptr_t)addr >= PMAP_START_ADDRESS &&
#else
           (1 &&
#endif
           ((uintptr_t)addr < PMAP_END_ADDRESS)) ||
           task_self () == task_get_kernel_task ());
}

// Copy bytes to userspace.
int user_copy_to (void *udst, const void *src, size_t size);

// Copy bytes from userspace.
int user_copy_from (void *dst, const void *usrc, size_t size);

// Same as above, only these operate on iovecs.
ssize_t user_copyv_to (struct iovec *udst, uint32_t nr_dst,
                       const struct iovec *src, uint32_t nr_src);

ssize_t user_copyv_from (struct iovec *dst, uint32_t nr_dst,
                         const struct iovec *usrc, uint32_t nr_src);

#endif