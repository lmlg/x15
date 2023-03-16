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

#include <stdint.h>
#include <uio.h>

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

// The following are macros to work around typing issues.
#define cap_base_acq(x)   sref_counter_inc (&((struct cap_base *)(x))->sref)
#define cap_base_rel(x)   sref_counter_dec (&((struct cap_base *)(x))->sref)

enum
{
  CAP_KERNEL_MEMORY,   // Allows mapping physical memory.
  CAP_KERNEL_DEVICE,   // Allows registering interrupts.
  CAP_KERNEL_MAX,
};

struct cap_intr_data;
struct cap_alert_node;

struct cap_intr_data
{
  BITMAP_DECLARE (pending, CPU_INTR_TABLE_SIZE);
  uint32_t nr_pending;
  struct list entries;
};

#define CAPABILITY   struct cap_base base

struct cap_flow
{
  CAPABILITY;
  struct spinlock lock;
  struct plist senders;
  struct list receivers;
  uint32_t flags;
  struct cap_intr_data intr;
  struct slist alert_list;
  struct cap_alert_node *alnodes;
  uintptr_t tag;
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

/* Intern a capability within the local space. Returns the new capability
 * index, or a negated errno value on error. */
int cap_intern (struct cap_base *cap, int flags);

#define cap_intern(cap, flags)   (cap_intern) (CAP (cap), (flags))

// Get the capability's type.
#define cap_type(cap)   (((const struct cap_base *)(x))->type)

// Create a flow.
int cap_flow_create (struct cap_flow **outp, uint32_t flags, uintptr_t tag);

// Create a channel for a flow.
int cap_channel_create (struct cap_channel **outp, struct cap_base *flow,
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

// Send a receive a full message and also get the metadata.
ssize_t cap_send_msg (struct cap_base *cap, const struct ipc_msg *src,
                      struct ipc_msg *dst, struct ipc_msg_data *data);

#define cap_send_msg(cap, src, dst, data)   \
  (cap_send_msg) (CAP (cap), (src), (dst), (data))

// Send an alert to a capability (flow or channel).
ssize_t cap_send_alert (struct cap_base *cap, const void *buf,
                        size_t size, uint32_t flags, uint32_t priority);

#define cap_send_alert(cap, buf, size, flags, prio)   \
  (cap_send_alert) (CAP (cap), (buf), (size), (flags), (prio))

// Reiceve a full message and the metadata.
rcvid_t cap_recv_msg (int capx, struct ipc_msg *msg,
                      struct ipc_msg_data *data);

// Reply to a received message with a full message structure or an error.
int cap_reply_msg (rcvid_t rcvid, const struct ipc_msg *msg, int err);

// Make the calling thread handle a message, or detach the current one if zero.
int cap_handle (rcvid_t rcvid);

/*
 * Pull more data from a receive ID.
 *
 * If the calling thread is not already handling the receive ID, then it is
 * acquired after detaching the current one (in case it's not being handled
 * by any other thread).
 */

ssize_t cap_pull_msg (rcvid_t rcvid, struct ipc_msg *msg,
                      struct ipc_msg_data *mdata);

/*
 * Push more data into a receive ID.
 *
 * If the calling thread is not already handling the receive ID, then it is
 * acquired after detaching the current one (in case it's not being handled
 * by any other thread).
 */

ssize_t cap_push_msg (rcvid_t rcvid, const struct ipc_msg *msg,
                      struct ipc_msg_data *mdata);

// Register a flow for interrupt handling.
int cap_intr_register (struct cap_flow *flow, uint32_t irq);

// Unregister a flow for interrupt handling.
int cap_intr_unregister (struct cap_flow *flow, uint32_t irq);

// Mark an interrupt for a flow as handled.
int cap_intr_eoi (struct cap_flow *flow, uint32_t irq);

// Inlined versions of the above.

#define CAP_IOV_MAKE(base, len)   \
  (struct iovec) { .iov_base = (void *)(base), .iov_len = (len) }

#define CAP_MSG_IOV_MAKE(iovs_, nr_iovs_)   \
  (struct ipc_msg) { .size = sizeof (struct ipc_msg),   \
                     .iovs = (struct iovec *)(iovs_),   \
                     .iov_cnt = (nr_iovs_),   \
                     .cap_cnt = 0, .page_cnt = 0 }

// Send raw bytes to a capability and receive the reply.
static inline ssize_t
cap_send_bytes (struct cap_base *cap, const void *src, size_t src_size,
                void *dst, size_t dst_size)
{
  struct iovec s_iov = CAP_IOV_MAKE (src, src_size),
               d_iov = CAP_IOV_MAKE (dst, dst_size);
  struct ipc_msg s_msg = CAP_MSG_IOV_MAKE (&s_iov, 1),
                 d_msg = CAP_MSG_IOV_MAKE (&d_iov, 1);

  return (cap_send_msg (cap, &s_msg, &d_msg, NULL));
}

#define cap_send_bytes(cap, src, src_size, dst, dst_size)   \
  (cap_send_bytes) (CAP (cap), (src), (src_size), (dst), (dst_size))

// Send bytes in iovecs and receive the reply.
static inline ssize_t
cap_send_iov (struct cap_base *cap, const struct iovec *src, uint32_t nr_src,
              struct iovec *dst, uint32_t nr_dst)
{
  struct ipc_msg s_msg = CAP_MSG_IOV_MAKE (src, nr_src),
                 d_msg = CAP_MSG_IOV_MAKE (dst, nr_dst);
  return (cap_send_msg (cap, &s_msg, &d_msg, NULL));
}

#define cap_send_iov(cap, src, nr_src, dst, nr_dst)   \
  (cap_send_iov) (CAP (cap), (src), (nr_src), (dst), (nr_dst))

// Receive raw bytes from a flow and the metadata.
static inline rcvid_t
cap_recv_bytes (int capx, void *dst, size_t size,
                struct ipc_msg_data *data)
{
  struct iovec vec = CAP_IOV_MAKE (dst, size);
  struct ipc_msg msg = CAP_MSG_IOV_MAKE (&vec, 1);
  return (cap_recv_msg (capx, &msg, data));
}

// Receive bytes in iovecs and the metadata.
static inline rcvid_t
cap_recv_iov (int capx, struct iovec *dst, uint32_t nr_iov,
              struct ipc_msg_data *data)
{
  struct ipc_msg msg = CAP_MSG_IOV_MAKE (dst, nr_iov);
  return (cap_recv_msg (capx, &msg, data));
}

// Reply to a received message with raw bytes or an error.
static inline int
cap_reply_bytes (rcvid_t rcvid, const void *src, size_t bytes, int err)
{
  struct iovec iov = CAP_IOV_MAKE (src, bytes);
  struct ipc_msg msg = CAP_MSG_IOV_MAKE (&iov, 1);
  return (cap_reply_msg (rcvid, &msg, err));
}

// Reply to a received message with bytes in iovecs or an error.
static inline int
cap_reply_iov (rcvid_t rcvid, const struct iovec *iov,
               uint32_t nr_iov, int err)
{
  struct ipc_msg msg = CAP_MSG_IOV_MAKE (iov, nr_iov);
  return (cap_reply_msg (rcvid, &msg, err));
}

// Pull raw bytes from a receive ID.
static inline ssize_t
cap_pull_bytes (rcvid_t rcvid, void *dst, size_t bytes,
                struct ipc_msg_data *mdata)
{
  struct iovec iov = CAP_IOV_MAKE (dst, bytes);
  struct ipc_msg msg = CAP_MSG_IOV_MAKE (&iov, 1);
  return (cap_pull_msg (rcvid, &msg, mdata));
}

// Pull iovecs from a receive ID.
static inline ssize_t
cap_pull_iov (rcvid_t rcvid, struct iovec *iovs, uint32_t nr_iovs,
              struct ipc_msg_data *mdata)
{
  struct ipc_msg msg = CAP_MSG_IOV_MAKE (iovs, nr_iovs);
  return (cap_pull_msg (rcvid, &msg, mdata));
}

// Push raw bytes into a receive ID.
static inline ssize_t
cap_push_bytes (rcvid_t rcvid, const void *src, size_t bytes,
                struct ipc_msg_data *mdata)
{
  struct iovec iov = CAP_IOV_MAKE (src, bytes);
  struct ipc_msg msg = CAP_MSG_IOV_MAKE (&iov, 1);
  return (cap_push_msg (rcvid, &msg, mdata));
}

// Push iovecs into a receive ID.
static inline ssize_t
cap_push_iov (rcvid_t rcvid, const struct iovec *iovs, uint32_t nr_iovs,
              struct ipc_msg_data *mdata)
{
  struct ipc_msg msg = CAP_MSG_IOV_MAKE (iovs, nr_iovs);
  return (cap_push_msg (rcvid, &msg, mdata));
}

#undef CAP_IOV_MAKE
#undef CAP_MSG_IOV_MAKE

/*
 * This init operation provides :
 *  - capabilities fully operational.
 */

INIT_OP_DECLARE (capability_setup);

#endif
