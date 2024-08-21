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

struct ipc_iov_iter;

// Type used for fast, unaligned access.
union user_ua
{
  unsigned u2 __attribute__ ((mode (HI)));
  unsigned u4 __attribute__ ((mode (SI)));
  unsigned u8 __attribute__ ((mode (DI)));
} __packed;

// Test that an address is accessible for the current task.
static inline bool
user_check_range (const void *addr, size_t size)
{
  return (
#if PMAP_START_ADDRESS > 0
          (uintptr_t)addr >= PMAP_START_ADDRESS &&
#else
          1 &&
#endif
          ((uintptr_t)addr + size < PMAP_END_ADDRESS));
}

// Copy bytes to userspace.
int user_copy_to (void *udst, const void *src, size_t size);

// Copy bytes from userspace.
int user_copy_from (void *dst, const void *usrc, size_t size);

// Same as above, only these operate on iovecs.
ssize_t user_copyv_to (struct ipc_iov_iter *udst, struct ipc_iov_iter *src);

ssize_t user_copyv_from (struct ipc_iov_iter *dst, struct ipc_iov_iter *usrc);

// Copy to/from userspace a struct that knows its size.
int user_read_struct (void *dst, const void *usrc, size_t size);

int user_write_struct (void *udst, const void *src, size_t size);

#endif
