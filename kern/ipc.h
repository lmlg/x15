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
 *
 * Definitions for inter-process communication.
 */

#ifndef KERN_IPC_H
#define KERN_IPC_H

#include <stdbool.h>
#include <stdint.h>
#include <uio.h>

#include <kern/types.h>

struct ipc_iterator
{
  struct iovec *iovs;
  int cur_iov;
  int nr_iovs;
  void *cur_ptr;
  size_t cur_size;
};

static inline void
ipc_iterator_set_invalid (struct ipc_iterator *it)
{
  it->cur_iov = -1;
}

static inline bool
ipc_iterator_valid (const struct ipc_iterator *it)
{
  return (it->cur_iov >= 0);
}

static inline void
ipc_iterator_init_buf (struct ipc_iterator *it, void *buf, size_t size)
{
  it->iovs = NULL;
  it->cur_iov = it->nr_iovs = 0;
  it->cur_ptr = buf;
  it->cur_size = size;

  if (! size)
    ipc_iterator_set_invalid (it);
}

static inline size_t
ipc_iterator_cur_size (const struct ipc_iterator *it)
{
  return (it->cur_size);
}

static inline void*
ipc_iterator_cur_ptr (const struct ipc_iterator *it)
{
  return ((void *)it->cur_ptr);
}

struct thread;

// Initialize an IPC iterator with a number of iovec's.
int ipc_iterator_init_iov (struct ipc_iterator *it,
                           struct iovec *iovs, uint32_t nr_iovs);

// Advance an IPC iterator by OFF bytes.
int ipc_iterator_adv (struct ipc_iterator *it, size_t off);

// Copy data through iterators.
ssize_t ipc_copy_iter (struct ipc_iterator *src_it, struct thread *src_thr,
                       struct ipc_iterator *dst_it, struct thread *dst_thr);

#endif
