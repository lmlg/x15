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
 * Interfaces for capabilities.
 */

#ifndef KERN_CAP_H
#define KERN_CAP_H

#include <assert.h>
#include <stdint.h>

#include <kern/hlist.h>
#include <kern/init.h>
#include <kern/ipc.h>
#include <kern/list.h>
#include <kern/pqueue.h>
#include <kern/slist.h>
#include <kern/spinlock.h>
#include <kern/sref.h>

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

#define CAP_ALERT_NONBLOCK   0x01   // Don't block when sending an alert.

// Alert types.
enum
{
  CAP_ALERT_USER,
  CAP_ALERT_INTR,
  CAP_ALERT_THREAD_DIED,
  CAP_ALERT_TASK_DIED,
  CAP_ALERT_CHAN_CLOSED,
};

// Kernel-sent alert.
struct cap_kern_alert
{
  int type;
  union
    {
      struct
        {
          uint32_t irq;
          uint32_t count;
        } intr;

      int thread_id;
      int task_id;
      int any_id;
      uintptr_t tag;
    };
};

static_assert (sizeof (struct cap_kern_alert) <= CAP_ALERT_SIZE,
               "struct cap_kern_alert is too big");

static_assert (OFFSETOF (struct cap_kern_alert, intr.irq) ==
               OFFSETOF (struct cap_kern_alert, thread_id) &&
               OFFSETOF (struct cap_kern_alert, thread_id) ==
               OFFSETOF (struct cap_kern_alert, task_id),
               "invalid layout for cap_kern_alert");

struct cap_base
{
  unsigned char type;
  unsigned int flags:24;
  struct sref_counter sref;
};

enum
{
  CAP_KERNEL_MEMORY,   // Allows mapping physical memory.
  CAP_KERNEL_DEVICE,   // Allows registering interrupts.
  CAP_KERNEL_MAX,
};

struct cap_thread_info
{
  struct futex_td *futex_td;
  void *thread_ptr;
};

#define CAPABILITY   struct cap_base base

#define CAP_FLOW_HANDLE_INTR   0x01   // Flow can handle interrupts.
#define CAP_FLOW_EXT_PAGER     0x02   // Flow is an external pager.

struct cap_flow
{
  CAPABILITY;
  struct list waiters;
  struct list receivers;
  struct slist lpads;
  struct hlist alloc_alerts;
  struct pqueue pending_alerts;
  uintptr_t tag;
  uintptr_t entry;
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
  struct ipc_vme_iter vme;
};

struct bulletin;

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
int cap_flow_create (struct cap_flow **outp, uint32_t flags,
                     uintptr_t tag, uintptr_t entry);

// Create a channel for a flow.
int cap_channel_create (struct cap_channel **outp, struct cap_flow *flow,
                        uintptr_t tag);

// Create a capability representing a task.
int cap_task_create (struct cap_task **outp, struct task *task);

// Create a capability representing a thread.
int cap_thread_create (struct cap_thread **outp, struct thread *thread);

// Get and set a capability's tag (Used for channels and flows).
int cap_get_tag (const struct cap_base *cap, uintptr_t *tagp);
int cap_set_tag (struct cap_base *cap, uintptr_t tag);

#define cap_get_tag(cap, tagp)   (cap_get_tag) (CAP (cap), (tagp))
#define cap_set_tag(cap, tag)    (cap_set_tag) (CAP (cap), (tag))

// Link a channel to a flow.
int cap_channel_link (struct cap_channel *channel, struct cap_flow *flow);

// Hook a channel to a remote flow in a task.
int cap_flow_hook (struct cap_channel **outp, struct task *task, int cap_idx);

// Send and receive iterator triplets to a capability.
ssize_t cap_send_iters (struct cap_base *cap, struct cap_iters *in_it,
                        struct cap_iters *out_it, struct ipc_msg_data *data);

// Reply to the current message with an iterator triplet or error value.
ssize_t cap_reply_iters (struct cap_iters *it, int rv);

// Pull an iterator triplet from the current message.
ssize_t cap_pull_iters (struct cap_iters *it, struct ipc_msg_data *data);

// Push an iterator triplet to the current message.
ssize_t cap_push_iters (struct cap_iters *it, struct ipc_msg_data *data);

// Receive an alert from a flow.
int cap_recv_alert (struct cap_flow *flow, void *buf,
                    uint32_t flags, struct ipc_msg_data *mdata);

// Send an alert to a flow.
int cap_send_alert (struct cap_base *cap, const void *buf,
                    uint32_t flags, uint32_t prio);

#define cap_send_alert(cap, buf, flags, prio)   \
  (cap_send_alert) (CAP (cap), buf, flags, prio)

// Add and remove a landing pad to/from a flow.
int cap_flow_add_lpad (struct cap_flow *flow, void *stack, size_t size,
                       struct ipc_msg *msg, struct ipc_msg_data *mdata,
                       struct cap_thread_info *info);

int cap_flow_rem_lpad (struct cap_flow *flow, uintptr_t stack);

// Register a flow for interrupt handling.
int cap_intr_register (struct cap_flow *flow, uint32_t irq);

// Unregister a flow for interrupt handling.
int cap_intr_unregister (struct cap_flow *flow, uint32_t irq);

// Register a thread on a flow to notify on its death.
int cap_thread_register (struct cap_flow *flow, struct thread *thread);

// Register a task on a flow to notify on its death.
int cap_task_register (struct cap_flow *flow, struct task *task);

// Unregister a thread.
int cap_thread_unregister (struct cap_flow *flow, struct thread *thread);

// Unregister a task.
int cap_task_unregister (struct cap_flow *flow, struct task *task);

// Traverse a list of dead notifications.
void cap_notify_dead (struct bulletin *bulletin);

#define cap_iters_init_impl(it, buf, size, iov_init)   \
  do   \
    {   \
      iov_init (&(it)->iov, (void *)(buf), size);   \
      ipc_cap_iter_init (&(it)->cap, 0, 0);   \
      ipc_vme_iter_init (&(it)->vme, 0, 0);   \
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
      ipc_vme_iter_init (&(it)->vme, (msg)->vmes, (msg)->vme_cnt);   \
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

// Reply to the current message with raw bytes or an error.
static inline int
cap_reply_bytes (const void *src, size_t bytes, int err)
{
  struct cap_iters it;
  cap_iters_init_buf (&it, src, bytes);
  return (cap_reply_iters (&it, err));
}

// Reply to the current message with bytes in iovecs or an error.
static inline int
cap_reply_iov (const struct iovec *iov, uint32_t nr_iov, int err)
{
  struct cap_iters it;
  cap_iters_init_iov (&it, iov, nr_iov);
  return (cap_reply_iters (&it, err));
}

// Reply to the current message with a full IPC message or an error.
static inline int
cap_reply_msg (const struct ipc_msg *msg, int err)
{
  struct cap_iters it;
  cap_iters_init_msg (&it, msg);
  return (cap_reply_iters (&it, err));
}

// Pull raw bytes from the current message.
static inline ssize_t
cap_pull_bytes (void *dst, size_t bytes, struct ipc_msg_data *mdata)
{
  struct cap_iters it;
  cap_iters_init_buf (&it, dst, bytes);
  return (cap_pull_iters (&it, mdata));
}

// Pull iovecs from the current message.
static inline ssize_t
cap_pull_iov (struct iovec *iovs, uint32_t nr_iovs, struct ipc_msg_data *mdata)
{
  struct cap_iters it;
  cap_iters_init_iov (&it, iovs, nr_iovs);
  return (cap_pull_iters (&it, mdata));
}

// Pull an IPC message from the current message.
static inline ssize_t
cap_pull_msg (struct ipc_msg *msg, struct ipc_msg_data *mdata)
{
  struct cap_iters it;
  cap_iters_init_msg (&it, msg);
  return (cap_pull_iters (&it, mdata));
}

// Push raw bytes into the current message.
static inline ssize_t
cap_push_bytes (const void *src, size_t bytes,
                struct ipc_msg_data *mdata)
{
  struct cap_iters it;
  cap_iters_init_buf (&it, src, bytes);
  return (cap_push_iters (&it, mdata));
}

// Push iovecs into the current message.
static inline ssize_t
cap_push_iov (const struct iovec *iovs, uint32_t nr_iovs,
              struct ipc_msg_data *mdata)
{
  struct cap_iters it;
  cap_iters_init_iov (&it, iovs, nr_iovs);
  return (cap_push_iters (&it, mdata));
}

// Push an IPC message to the current message.
static inline ssize_t
cap_push_msg (const struct ipc_msg *msg, struct ipc_msg_data *mdata)
{
  struct cap_iters it;
  cap_iters_init_msg (&it, msg);
  return (cap_push_iters (&it, mdata));
}

/*
 * This init operation provides :
 *  - capabilities fully operational.
 */

INIT_OP_DECLARE (cap_setup);

#endif
