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
 * Interfaces for capabilities.
 */

#ifndef KERN_CAPABILITY_H
#define KERN_CAPABILITY_H

#include <iovec.h>
#include <stdint.h>

#include <kern/bitmap.h>
#include <kern/init.h>
#include <kern/ipc.h>
#include <kern/list.h>
#include <kern/plist.h>
#include <kern/slist.h>
#include <kern/spinlock.h>
#include <kern/sref.h>

#include <machine/cpu.h>

struct task;
struct thread;

enum
{
  CAP_TYPE_CHANNEL,
  CAP_TYPE_FLOW,
  CAP_TYPE_TASK,
  CAP_TYPE_THREAD,
  CAP_TYPE_KERNEL,
  CAP_TYPE_MAX,
};

// Size of an alert message, in bytes.
#define CAP_ALERT_SIZE   16

typedef int64_t rcvid_t;

struct cap_base
{
  unsigned int type;
  struct sref_counter sref;
};

enum
{
  CAP_KERNEL_MEMORY,   // Allows mapping physical memory.
  CAP_KERNEL_DEVICE,   // Allows registering interrupts.
  CAP_KERNEL_MAX,
};

#define CAPABILITY   struct cap_base base

struct cap_flow
{
  CAPABILITY;
  struct plist senders;
  struct list receivers;
  struct
    {
      BITMAP_DECLARE (pending, CPU_INTR_TABLE_SIZE);
      struct list entries;
      uint32_t nr_pending;
    } intr;
  uint32_t flags;
  struct slist alert_list;
  uintptr_t tag;
#if CONFIG_MAX_CPUS > 1
  char pad[CPU_L1_SIZE];
#endif
  struct spinlock lock;
};

struct cap_channel
{
  CAPABILITY;
  struct cap_flow *flow;
  uintptr_t tag;
};

struct cap_task
{
  CAPABILITY;
  struct task *task;
};

struct cap_thread
{
  CAPABILITY;
  struct thread *thread;
};

struct cap_kernel
{
  CAPABILITY;
  int kind;
};

// Triplet of iterators.
struct cap_iters
{
  struct ipc_iov_iter iov;
  struct ipc_cap_iter cap;
  struct ipc_page_iter page;
};

// Cast a capability to the base type.

#define CAP_BASE(x)   ((struct cap_base *)(x))

#define CAP(x)   \
  _Generic (x,   \
            struct cap_kernel * : CAP_BASE (x),   \
            struct cap_thread * : CAP_BASE (x),   \
            struct cap_task *   : CAP_BASE (x),   \
            struct cap_channel *: CAP_BASE (x),   \
            struct cap_flow *   : CAP_BASE (x),   \
            default: (x))

// Flags for 'cap_send_alert'.
#define CAP_ALERT_ASYNC   0x00
#define CAP_ALERT_BLOCK   0x01

// Acquire or release a reference on a capability.
static inline void
cap_base_acq (struct cap_base *cap)
{
  sref_counter_inc (&cap->sref);
}

static inline void
cap_base_rel (struct cap_base *cap)
{
  sref_counter_dec (&cap->sref);
}

#define cap_base_acq(cap)   (cap_base_acq) (CAP (cap))
#define cap_base_rel(cap)   (cap_base_rel) (CAP (cap))

/*
 * Intern a capability within the local space. Returns the new capability
 * index, or a negated errno value on error.
 */
int cap_intern (struct cap_base *cap, int flags);

#define cap_intern(cap, flags)   (cap_intern) (CAP (cap), (flags))

// Get the capability's type.
#define cap_type(cap)   (((const struct cap_base *)(x))->type)

// Create a flow.
int cap_flow_create (struct cap_flow **outp, uint32_t flags, uintptr_t tag);

// Create a channel for a flow.
int cap_channel_create (struct cap_channel **outp, struct cap_flow *flow,
                        uintptr_t tag);

// Create a capability representing a task.
int cap_task_create (struct cap_task **outp, struct task *task);

// Create a capability representing a thread.
int cap_thread_create (struct cap_thread **outp, struct thread *thread);

// Get and set a capability's tag (Used for channels and flows).
int cap_get_tag (const struct cap_base *cap, uintptr_t *tagp);

#define cap_get_tag(cap, tagp)   (cap_get_tag) (CAP (cap), (tagp))

int cap_set_tag (struct cap_base *cap, uintptr_t tag);

#define cap_set_tag(cap, tag)    (cap_set_tag) (CAP (cap), (tag))

// Link a channel to a flow.
int cap_channel_link (struct cap_channel *channel, struct cap_flow *flow);

// Hook a channel to a remote flow in a task.
int cap_flow_hook (struct cap_channel **outp, struct task *task, int cap_idx);

// Send and receive IPC iterators and get the metadata.
ssize_t cap_send_iters (struct cap_base *cap, struct cap_iters *in,
                        struct cap_iters *out, struct ipc_msg_data *data);

// Send an alert to a capability (flow or channel).
ssize_t cap_send_alert (struct cap_base *cap, const void *buf,
                        size_t size, uint32_t flags, uint32_t priority);

#define cap_send_alert(cap, buf, size, flags, prio)   \
  (cap_send_alert) (CAP (cap), (buf), (size), (flags), (prio))

// Receive IPC iterators and the metadata.
rcvid_t cap_recv_iter (int capx, struct cap_iters *it,
                       struct ipc_msg_data *data);

// Reply to a received message with IPC iterators or an error.
int cap_reply_iter (rcvid_t rcvid, struct cap_iters *iter, int err);

/*
 * Make the calling thread handle a receive ID, or detach the
 * current one if zero.
 */
int cap_handle (rcvid_t rcvid);

/*
 * Pull more data from a receive ID.
 *
 * If the calling thread is not already handling the receive ID, then it will
 * attempt to acquire it after detaching its current peer.
 */
ssize_t cap_pull_iter (rcvid_t rcvid, struct cap_iters *iter,
                       struct ipc_msg_data *mdata);

/*
 * Push more data into a receive ID.
 *
 * If the calling thread is not already handling the receive ID, then it will
 * attempt to acquire it after detaching its current peer.
 */
ssize_t cap_push_iter (rcvid_t rcvid, struct cap_iters *iter,
                       struct ipc_msg_data *mdata);

// Redirect a previously received message to a new capability.
int cap_redirect (rcvid_t rcvid, struct cap_base *cap);

// Register a flow for interrupt handling.
int cap_intr_register (struct cap_flow *flow, uint32_t irq);

// Unregister a flow for interrupt handling.
int cap_intr_unregister (struct cap_flow *flow, uint32_t irq);

// Mark an interrupt for a flow as handled.
int cap_intr_eoi (struct cap_flow *flow, uint32_t irq);

// Inlined versions of the above.

#define cap_iters_init_impl(it, buf, size, iov_init)   \
  do   \
    {   \
      iov_init (&(it)->iov, (void *)(buf), size);   \
      ipc_cap_iter_init (&(it)->cap, 0, 0);   \
      ipc_page_iter_init (&(it)->page, 0, 0);   \
    }   \
  while (0)

#define cap_iters_init_buf(it, buf, size)   \
  cap_iters_init_impl (it, buf, size, ipc_iov_iter_init_buf)

#define cap_iters_init_iov(it, iovs, nr_iovs)   \
  cap_iters_init_impl (it, iovs, nr_iovs, ipc_iov_iter_init)

#define cap_iters_init_msg(it, msg)   \
  do   \
    {   \
      ipc_iov_iter_init (&(it)->iov, (msg)->iovs, (msg)->iov_cnt);   \
      ipc_cap_iter_init (&(it)->cap, (msg)->caps, (msg)->cap_cnt);   \
      ipc_page_iter_init (&(it)->page, (msg)->pages, (msg)->page_cnt);   \
    }   \
  while (0)

// Send raw bytes to a capability and receive the reply.
static inline ssize_t
cap_send_bytes (struct cap_base *cap, const void *src, size_t src_size,
                void *dst, size_t dst_size)
{
  struct cap_iters in, out;

  cap_iters_init_buf (&in, src, src_size);
  cap_iters_init_buf (&out, dst, dst_size);

  return (cap_send_iters (cap, &in, &out, NULL));
}

#define cap_send_bytes(cap, src, src_size, dst, dst_size)   \
  (cap_send_bytes) (CAP (cap), (src), (src_size), (dst), (dst_size))

// Send bytes in iovecs and receive the reply.
static inline ssize_t
cap_send_iov (struct cap_base *cap, const struct iovec *src, uint32_t nr_src,
              struct iovec *dst, uint32_t nr_dst)
{
  struct cap_iters in, out;

  cap_iters_init_iov (&in, src, nr_src);
  cap_iters_init_iov (&out, dst, nr_dst);

  return (cap_send_iters (cap, &in, &out, NULL));
}

#define cap_send_iov(cap, src, nr_src, dst, nr_dst)   \
  (cap_send_iov) (CAP (cap), (src), (nr_src), (dst), (nr_dst))

// Send and receive full messages and also the metadata.
static inline ssize_t
cap_send_msg (struct cap_base *cap, const struct ipc_msg *src,
              struct ipc_msg *dst, struct ipc_msg_data *data)
{
  struct cap_iters in, out;

  cap_iters_init_msg (&in, src);
  cap_iters_init_msg (&out, dst);
  return (cap_send_iters (cap, &in, &out, data));
}

#define cap_send_msg(cap, src, dst, data)   \
  (cap_send_msg) (CAP (cap), (src), (dst), (data))

// Receive raw bytes and metadata from a capability.
static inline rcvid_t
cap_recv_bytes (int capx, void *dst, size_t size,
                struct ipc_msg_data *data)
{
  struct cap_iters in;
  cap_iters_init_buf (&in, dst, size);
  return (cap_recv_iter (capx, &in, data));
}

// Receive bytes in iovecs and metadata from a capability.
static inline rcvid_t
cap_recv_iov (int capx, struct iovec *dst, uint32_t nr_iov,
              struct ipc_msg_data *data)
{
  struct cap_iters in;
  cap_iters_init_iov (&in, dst, nr_iov);
  return (cap_recv_iter (capx, &in, data));
}

// Receive a full IPC message and metadata from a capability.
static inline rcvid_t
cap_recv_msg (int capx, struct ipc_msg *msg, struct ipc_msg_data *data)
{
  struct cap_iters in;
  cap_iters_init_msg (&in, msg);
  return (cap_recv_iter (capx, &in, data));
}

// Reply to a received message with raw bytes or an error.
static inline int
cap_reply_bytes (rcvid_t rcvid, const void *src, size_t bytes, int err)
{
  struct cap_iters it;
  cap_iters_init_buf (&it, src, bytes);
  return (cap_reply_iter (rcvid, &it, err));
}

// Reply to a received message with bytes in iovecs or an error.
static inline int
cap_reply_iov (rcvid_t rcvid, const struct iovec *iov,
               uint32_t nr_iov, int err)
{
  struct cap_iters it;
  cap_iters_init_iov (&it, iov, nr_iov);
  return (cap_reply_iter (rcvid, &it, err));
}

// Reply to a received message with a full IPC message or an error.
static inline int
cap_reply_msg (rcvid_t rcvid, const struct ipc_msg *msg, int err)
{
  struct cap_iters it;
  cap_iters_init_msg (&it, msg);
  return (cap_reply_iter (rcvid, &it, err));
}

// Pull raw bytes from a receive ID.
static inline ssize_t
cap_pull_bytes (rcvid_t rcvid, void *dst, size_t bytes,
                struct ipc_msg_data *mdata)
{
  struct cap_iters it;
  cap_iters_init_buf (&it, dst, bytes);
  return (cap_pull_iter (rcvid, &it, mdata));
}

// Pull iovecs from a receive ID.
static inline ssize_t
cap_pull_iov (rcvid_t rcvid, struct iovec *iovs, uint32_t nr_iovs,
              struct ipc_msg_data *mdata)
{
  struct cap_iters it;
  cap_iters_init_iov (&it, iovs, nr_iovs);
  return (cap_pull_iter (rcvid, &it, mdata));
}

// Pull an IPC message from a receive ID.
static inline ssize_t
cap_pull_msg (rcvid_t rcvid, struct ipc_msg *msg, struct ipc_msg_data *mdata)
{
  struct cap_iters it;
  cap_iters_init_msg (&it, msg);
  return (cap_pull_iter (rcvid, &it, mdata));
}

// Push raw bytes into a receive ID.
static inline ssize_t
cap_push_bytes (rcvid_t rcvid, const void *src, size_t bytes,
                struct ipc_msg_data *mdata)
{
  struct cap_iters it;
  cap_iters_init_buf (&it, src, bytes);
  return (cap_push_iter (rcvid, &it, mdata));
}

// Push iovecs into a receive ID.
static inline ssize_t
cap_push_iov (rcvid_t rcvid, const struct iovec *iovs, uint32_t nr_iovs,
              struct ipc_msg_data *mdata)
{
  struct cap_iters it;
  cap_iters_init_iov (&it, iovs, nr_iovs);
  return (cap_push_iter (rcvid, &it, mdata));
}

static inline ssize_t
cap_push_msg (rcvid_t rcvid, const struct ipc_msg *msg,
              struct ipc_msg_data *mdata)
{
  struct cap_iters it;
  cap_iters_init_msg (&it, msg);
  return (cap_push_iter (rcvid, &it, mdata));
}

/*
 * This init operation provides :
 *  - capabilities fully operational.
 */

INIT_OP_DECLARE (capability_setup);

#endif
