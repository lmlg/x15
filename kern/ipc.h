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

#include <iovec.h>
#include <stdbool.h>
#include <stdint.h>

#include <kern/types.h>

struct ipc_msg_page
{
  uintptr_t addr;
  size_t size;
  int prot;
};

struct ipc_msg_cap
{
  int cap;
  int flags;
};

#define IPC_IOV_ITER_CACHE_SIZE   8

struct ipc_iov_iter
{
  struct iovec cache[IPC_IOV_ITER_CACHE_SIZE];
  uint32_t cache_idx;
  struct iovec head;
  struct iovec *begin;
  uint32_t cur;
  uint32_t end;
};

struct ipc_cap_iter
{
  struct ipc_msg_cap *begin;
  uint32_t cur;
  uint32_t end;
};

struct ipc_page_iter
{
  struct ipc_msg_page *begin;
  uint32_t cur;
  uint32_t end;
};

struct ipc_msg
{
  size_t size;
  struct iovec *iovs;
  uint32_t iov_cnt;
  struct ipc_msg_page *pages;
  uint32_t page_cnt;
  struct ipc_msg_cap *caps;
  uint32_t cap_cnt;
};

// Bits for the 'flags' member of a IPC message metadata.
#define IPC_MSG_INTR   0x01   // Message was an interrupt.

struct ipc_msg_data
{
  size_t size;
  int task_id;
  int thread_id;
  uint32_t flags;
  uintptr_t tag;
  size_t nbytes;
  uint32_t pages_sent;
  uint32_t pages_recv;
  uint32_t caps_sent;
  uint32_t caps_recv;
};

struct task;

// Direction of the binary copy, relative to the remote task.
#define IPC_COPY_FROM   0
#define IPC_COPY_TO     1

/*
 * IPC iterator functions.
 *
 * These come in 3 flavors: iovec, capabilities and pages. The former works
 * by simply copying data; the other 2 by transfering objects across tasks.
 */

static inline void
ipc_cap_iter_init (struct ipc_cap_iter *it,
                   struct ipc_msg_cap *msg, uint32_t nr_msgs)
{
  it->begin = msg;
  it->cur = 0, it->end = nr_msgs;
}

static inline int
ipc_cap_iter_size (const struct ipc_cap_iter *it)
{
  return ((int)(it->end - it->cur));
}

static inline void
ipc_page_iter_init (struct ipc_page_iter *it,
                    struct ipc_msg_page *msg, uint32_t nr_msgs)
{
  it->begin = msg;
  it->cur = 0, it->end = nr_msgs;
}

static inline int
ipc_page_iter_size (const struct ipc_page_iter *it)
{
  return ((int)(it->end - it->cur));
}

static inline void
ipc_iov_iter_init_buf (struct ipc_iov_iter *it, void *buf, size_t size)
{
  it->head = IOVEC (buf, size);
  it->cache_idx = IPC_IOV_ITER_CACHE_SIZE;
  it->begin = &it->head;
  it->cur = it->end = 1;
}

static inline bool
ipc_iov_iter_empty (const struct ipc_iov_iter *it)
{
  return (it->cur >= it->end && !it->head.iov_len &&
          it->cache_idx >= IPC_IOV_ITER_CACHE_SIZE);
}

static inline void
ipc_iov_iter_init (struct ipc_iov_iter *it, struct iovec *vecs, uint32_t cnt)
{
  it->head.iov_len = 0;
  it->begin = vecs;
  it->cur = 0, it->end = cnt;
  it->cache_idx = IPC_IOV_ITER_CACHE_SIZE;
}

// Copy bytes between a local and a remote task.
ssize_t ipc_bcopy (struct task *r_task, void *r_ptr, size_t r_size,
                   void *l_ptr, size_t l_size, int direction);

// Copy bytes in iterators between a local and a remote task.
ssize_t ipc_iov_iter_copy (struct task *r_task, struct ipc_iov_iter *r_it,
                           struct ipc_iov_iter *l_it, int direction);

// Transfer capabilities in iterators between a local and a remote task.
int ipc_cap_iter_copy (struct task *r_task, struct ipc_cap_iter *r_it,
                       struct ipc_cap_iter *l_it, int direction);

// Transfer pages in iterators between a local and a remote task.
int ipc_page_iter_copy (struct task *r_task, struct ipc_page_iter *r_it,
                        struct ipc_page_iter *l_it, int direction);

// Copy bytes in iovecs between a local and a remote task.
static inline ssize_t
ipc_bcopyv (struct task *r_task, struct iovec *r_iov, uint32_t r_niov,
            struct iovec *l_iov, uint32_t l_niov, int direction)
{
  struct ipc_iov_iter r_it, l_it;
  ipc_iov_iter_init (&l_it, l_iov, l_niov);
  ipc_iov_iter_init (&r_it, r_iov, r_niov);
  return (ipc_iov_iter_copy (r_task, &r_it, &l_it, direction));
}

// Transfer pages between a remote and a local task.
static inline int
ipc_copy_pages (struct task *r_task, struct ipc_msg_page *r_pages,
                uint32_t r_npages, struct ipc_msg_page *l_pages,
                uint32_t l_npages, int direction)
{
  struct ipc_page_iter r_it, l_it;
  ipc_page_iter_init (&r_it, r_pages, r_npages);
  ipc_page_iter_init (&l_it, l_pages, l_npages);
  return (ipc_page_iter_copy (r_task, &r_it, &l_it, direction));
}

// Transfer capabilities between a remote and a local task.
static inline int
ipc_copy_caps (struct task *r_task, struct ipc_msg_cap *r_caps,
               uint32_t r_ncaps, struct ipc_msg_cap *l_caps,
               uint32_t l_ncaps, int direction)
{
  struct ipc_cap_iter r_it, l_it;
  ipc_cap_iter_init (&r_it, r_caps, r_ncaps);
  ipc_cap_iter_init (&l_it, l_caps, l_ncaps);
  return (ipc_cap_iter_copy (r_task, &r_it, &l_it, direction));
}

#endif
