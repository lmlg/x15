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

#define IPC_IOV_CACHE_SIZE   8

struct ipc_iov_cache
{
  struct iovec iovs[IPC_IOV_CACHE_SIZE];
  int idx;
  int size;
};

struct ipc_iter
{
  struct iovec *iovs;
  int cur_iov;
  int nr_iovs;
  struct iovec cur;
  struct ipc_iov_cache cache;
};

static inline void
ipc_iter_set_invalid (struct ipc_iter *it)
{
  it->cur_iov = -1;
}

static inline bool
ipc_iter_valid (const struct ipc_iter *it)
{
  return (it->cur_iov >= 0);
}

static inline void
ipc_iter_init_buf (struct ipc_iter *it, void *buf, size_t size)
{
  it->iovs = NULL;
  it->cur_iov = it->nr_iovs = 0;
  it->cur.iov_base = buf;
  it->cur.iov_len = size;
  it->cache.idx = it->cache.size = 0;

  if (! size)
    ipc_iter_set_invalid (it);
}

static inline size_t
ipc_iter_cur_size (const struct ipc_iter *it)
{
  return (it->cur.iov_len);
}

static inline void*
ipc_iter_cur_ptr (const struct ipc_iter *it)
{
  return ((void *)it->cur.iov_base);
}

struct thread;

// Initialize an IPC iterator with a number of iovec's.
int ipc_iter_init_iov (struct ipc_iter *it,
                           struct iovec *iovs, uint32_t nr_iovs);

// Advance an IPC iterator by OFF bytes.
int ipc_iter_adv (struct ipc_iter *it, size_t off);

/* Copy data through iterators. Returns the number of bytes copied,
 * or a negative value if there was an error. */
ssize_t ipc_copy_iter (struct ipc_iter *src_it, struct thread *src_thr,
                       struct ipc_iter *dst_it, struct thread *dst_thr);

#endif
