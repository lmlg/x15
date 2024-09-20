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
 */

#include <kern/capability.h>
#include <kern/cspace.h>
#include <kern/intr.h>
#include <kern/kmem.h>
#include <kern/kmessage.h>
#include <kern/rcu.h>
#include <kern/shell.h>
#include <kern/stream.h>
#include <kern/thread.h>

#include <machine/pmap.h>

#include <vm/map.h>
#include <vm/page.h>

#include <stdio.h>

struct cap_alert
{
  union
    {
      struct
        { // Valid for user alerts and when not pending.
          int task_id;
          int thread_id;
          uintptr_t tag;
        };

      struct hlist_node hnode;
    };

  struct pqueue_node pnode;
  int alert_type;
  union
    {
      char payload[CAP_ALERT_SIZE];
      struct cap_kern_alert k_alert;
    };
};

#define CAP_F(name)   OFFSETOF (struct ipc_msg_data, name)

static_assert (CAP_F (caps_recv) - CAP_F (bytes_recv) ==
               CAP_F (caps_sent) - CAP_F (bytes_sent) &&
               CAP_F (vmes_recv) - CAP_F (bytes_recv) ==
               CAP_F (vmes_sent) - CAP_F (bytes_sent),
               "invalid layout for struct ipc_msg_data");

#define CAP_VMES_OFF   (CAP_F (vmes_recv) - CAP_F (bytes_recv))
#define CAP_CAPS_OFF   (CAP_F (caps_recv) - CAP_F (bytes_recv))

struct cap_alert_async
{
  struct cap_alert base;
  struct list xlink;
  struct cap_flow *flow;
};

struct cap_lpad
{
  union
    {
      struct slist_node snode;
      struct cap_base *src;
    };

  struct task *task;
  size_t size;
  uintptr_t ctx[3];   // SP and function arguments.
  struct ipc_msg_data mdata;
  uint16_t nr_cached_iovs;
  uint16_t xflags;
  struct cap_iters in_it;
  struct cap_iters *cur_in;
  struct cap_iters *cur_out;
};

struct cap_receiver
{
  struct list lnode;
  struct thread *thread;
  void *buf;
  struct ipc_msg_data mdata;
  bool spurious;
};

struct cap_sender
{
  struct list lnode;
  struct thread *thread;
};

#define CAP_CHMAP_DFL_SIZE   32

static struct kmem_cache cap_flow_cache;
static struct kmem_cache cap_misc_cache;
static struct kmem_cache cap_lpad_cache;

static struct list cap_intr_handlers[CPU_INTR_TABLE_SIZE];
static struct adaptive_lock cap_intr_lock;

// Priorities for kernel-generated alerts.
#define CAP_ALERT_TASK_PRIO      ((THREAD_SCHED_RT_PRIO_MAX + 2) << 1)
#define CAP_ALERT_THREAD_PRIO    (CAP_ALERT_TASK_PRIO << 1)
#define CAP_ALERT_INTR_PRIO      (CAP_ALERT_THREAD_PRIO << 1)
#define CAP_ALERT_CHANNEL_PRIO   (1u)

#define CAP_CHANNEL_SHARED   0x01

#define CAP_FROM_SREF(ptr, type)   structof (ptr, type, base.sref)

// Forward declarations.
static void cap_recv_wakeup_fast (struct cap_flow *);
static void cap_intr_rem (uint32_t irq, struct list *link);

static void
cap_base_init (struct cap_base *base, uint32_t type, sref_noref_fn_t noref)
{
  assert (type < CAP_TYPE_MAX);
  base->tflags = ((uintptr_t)type << (sizeof (uintptr_t) * 8 - 8));
  sref_counter_init (&base->sref, 1, NULL, noref);
}

static void
cap_task_fini (struct sref_counter *sref)
{
  _Auto tp = CAP_FROM_SREF (sref, struct cap_task);
  task_unref (tp->task);
  kmem_cache_free (&cap_misc_cache, tp);
}

int
cap_task_create (struct cap_task **outp, struct task *task)
{
  struct cap_task *ret = kmem_cache_alloc (&cap_misc_cache);
  if (! ret)
    return (ENOMEM);

  cap_base_init (&ret->base, CAP_TYPE_TASK, cap_task_fini);
  task_ref (task);
  ret->task = task;
  *outp = ret;
  return (0);
}

static void
cap_thread_fini (struct sref_counter *sref)
{
  _Auto tp = CAP_FROM_SREF (sref, struct cap_thread);
  thread_unref (tp->thread);
  kmem_cache_free (&cap_misc_cache, tp);
}

int
cap_thread_create (struct cap_thread **outp, struct thread *thread)
{
  struct cap_thread *ret = kmem_cache_alloc (&cap_misc_cache);
  if (! ret)
    return (ENOMEM);

  cap_base_init (&ret->base, CAP_TYPE_THREAD, cap_thread_fini);
  thread_ref (thread);
  ret->thread = thread;
  *outp = ret;
  return (0);
}

static struct spinlock_guard
cap_flow_guard_make (struct cap_flow *flow)
{
  bool save_intr = (flow->base.tflags & CAP_FLOW_HANDLE_INTR) != 0;
  return (spinlock_guard_make (&flow->lock, save_intr));
}

#define cap_flow_guard_lock   spinlock_guard_lock
#define cap_flow_guard_fini   spinlock_guard_fini

static int
cap_alert_type (const struct cap_alert *alert)
{
  return (alert->alert_type);
}

static void
cap_alert_init_nodes (struct cap_alert *alert, uint32_t type, uint32_t prio)
{
  pqueue_node_init (&alert->pnode, prio);
  alert->alert_type = (int)type;
  hlist_node_init (&alert->hnode);
}

#define CAP_FLOW_GUARD(flow)   \
  CLEANUP (cap_flow_guard_fini) _Auto __unused UNIQ (cfg) =   \
    cap_flow_guard_make (flow)

static void
cap_channel_fini (struct sref_counter *sref)
{
  _Auto chp = CAP_FROM_SREF (sref, struct cap_channel);
  _Auto flow = chp->flow;

  uintptr_t tag = chp->tag;
  // Mutate the type.
  struct cap_alert *alert __attribute__ ((may_alias)) = (void *)chp;

  alert->k_alert.type = CAP_ALERT_CHAN_CLOSED;
  alert->k_alert.tag = tag;
  cap_alert_init_nodes (alert, CAP_ALERT_CHAN_CLOSED, CAP_ALERT_CHANNEL_PRIO);

  _Auto guard = cap_flow_guard_make (flow);
  hlist_insert_head (&flow->alloc_alerts, &alert->hnode);
  pqueue_insert (&flow->pending_alerts, &alert->pnode);
  cap_recv_wakeup_fast (flow);
  cap_flow_guard_fini (&guard);

  cap_base_rel (flow);
}

int
cap_channel_create (struct cap_channel **outp, struct cap_flow *flow,
                    uintptr_t tag)
{
  struct cap_channel *ret = kmem_cache_alloc (&cap_misc_cache);
  if (! ret)
    return (ENOMEM);

  cap_base_init (&ret->base, CAP_TYPE_CHANNEL, cap_channel_fini);

  if (flow)
    cap_base_acq (flow);

  ret->flow = flow;
  ret->tag = tag;
  ret->vmobj = NULL;
  *outp = ret;
  return (0);
}

static void
cap_task_thread_rem (int id, int type, struct list *link)
{
  _Auto kuid = kuid_find (id, type == CAP_ALERT_THREAD_DIED ?
                              KUID_THREAD : KUID_TASK);

#define cap_unlink_alert(obj, type, unref)   \
  do   \
    {   \
      _Auto ptr = structof (obj, type, kuid);   \
      spinlock_lock (&ptr->dead_subs.lock);   \
      list_remove (link);   \
      spinlock_unlock (&ptr->dead_subs.lock);   \
      unref (ptr);   \
    }   \
  while (0)

  if (! kuid)
    return;
  else if (type == CAP_ALERT_THREAD_DIED)
    cap_unlink_alert (kuid, struct thread, thread_unref);
  else
    cap_unlink_alert (kuid, struct task, task_unref);

#undef cap_unlink_alert
}

static void
cap_alert_free (struct cap_alert *alert)
{
  _Auto async = (struct cap_alert_async *)alert;
  _Auto k_alert = &alert->k_alert;
  int type = cap_alert_type (alert);

  if (type == CAP_ALERT_INTR)
    cap_intr_rem (k_alert->intr.irq, &async->xlink);
  else if (type == CAP_ALERT_THREAD_DIED || type == CAP_ALERT_TASK_DIED)
    cap_task_thread_rem (k_alert->any_id, type, &async->xlink);

  kmem_cache_free (&cap_misc_cache, alert);
}

static void
cap_lpad_fini (struct cap_lpad *lpad)
{
  task_unref (lpad->task);
  kmem_cache_free (&cap_lpad_cache, lpad);
}

static void
cap_flow_fini (struct sref_counter *sref)
{
  _Auto flow = CAP_FROM_SREF (sref, struct cap_flow);

  struct cap_alert *alert, *tmp;
  pqueue_for_each_entry_safe (&flow->pending_alerts, alert, tmp, pnode)
    if (cap_alert_type (alert) == CAP_ALERT_USER)
      kmem_cache_free (&cap_misc_cache, alert);

  hlist_for_each_entry_safe (&flow->alloc_alerts, alert, tmp, hnode)
    cap_alert_free (alert);

  struct cap_lpad *lpad, *pt;
  slist_for_each_entry_safe (&flow->lpads, lpad, pt, snode)
    cap_lpad_fini (lpad);

  kmem_cache_free (&cap_flow_cache, flow);
}

#define CAP_FLOW_VALID_FLAGS   \
  (CAP_FLOW_HANDLE_INTR | CAP_FLOW_EXT_PAGER | CAP_FLOW_PAGER_FLUSHES)

int
cap_flow_create (struct cap_flow **outp, uint32_t flags,
                 uintptr_t tag, uintptr_t entry)
{
  if (flags & ~CAP_FLOW_VALID_FLAGS)
    return (EINVAL);

  struct cap_flow *ret = kmem_cache_alloc (&cap_flow_cache);
  if (! ret)
    return (ENOMEM);

  cap_base_init (&ret->base, CAP_TYPE_FLOW, cap_flow_fini);
  spinlock_init (&ret->lock);
  list_init (&ret->waiters);
  list_init (&ret->receivers);
  slist_init (&ret->lpads);
  hlist_init (&ret->alloc_alerts);
  pqueue_init (&ret->pending_alerts);
  ret->base.tflags |= flags;
  ret->tag = tag;
  ret->entry = entry;

  *outp = ret;
  return (0);
}

int
(cap_get_tag) (const struct cap_base *cap, uintptr_t *tagp)
{
  switch (cap_type (cap))
    {
      case CAP_TYPE_CHANNEL:
        *tagp = ((const struct cap_channel *)cap)->tag;
        return (0);

      case CAP_TYPE_FLOW:
        *tagp = ((const struct cap_flow *)cap)->tag;
        return (0);

      default:
        return (EINVAL);
    }
}

int
cap_flow_hook (struct cap_channel **outp, struct task *task, int capx)
{
  struct cap_base *base = cspace_get (&task->caps, capx);
  if (! base)
    return (EBADF);
  else if (cap_type (base) != CAP_TYPE_FLOW)
    {
      cap_base_rel (base);
      return (EINVAL);
    }

  _Auto flow = (struct cap_flow *)base;
  int ret = cap_channel_create (outp, flow, flow->tag);
  cap_base_rel (flow);
  return (ret);
}


/*
 * Transfer all 3 iterators between a local and a remote task.
 * Updates the metadata if succesful. Returns the number of
 * raw bytes transmitted on success; a negative errno value on failure.
 */

static ssize_t
cap_transfer_iters (struct task *task, struct cap_iters *r_it,
                    struct cap_iters *l_it, uint32_t flags, ssize_t *bytesp)
{
  ssize_t ret = ipc_iov_iter_copy (task, &r_it->iov, &l_it->iov, flags);
  if (ret < 0)
    return (ret);

  *bytesp += ret;
  if (ipc_cap_iter_size (&r_it->cap) && ipc_cap_iter_size (&l_it->cap))
    {
      int nr_caps = ipc_cap_iter_copy (task, &r_it->cap, &l_it->cap, flags);
      if (nr_caps < 0)
        return (nr_caps);

      *(uint32_t *)((char *)bytesp + CAP_CAPS_OFF) += nr_caps;
    }

  if (ipc_vme_iter_size (&r_it->vme) && ipc_vme_iter_size (&l_it->vme))
    {
      int nr_vmes = ipc_vme_iter_copy (task, &r_it->vme, &l_it->vme, flags);
      if (nr_vmes < 0)
        return (nr_vmes);

      *(uint32_t *)((char *)bytesp + CAP_VMES_OFF) += nr_vmes;
    }

  return (ret);
}

static struct cap_alert*
cap_flow_alloc_alert (struct spinlock_guard *guard, uint32_t flg)
{
  cap_flow_guard_fini (guard);
  uint32_t alflags = (flg & CAP_ALERT_NONBLOCK) ? 0 : KMEM_ALLOC_SLEEP;
  void *ptr = kmem_cache_alloc2 (&cap_misc_cache, alflags);
  cap_flow_guard_lock (guard);
  return (ptr);
}

static void
cap_receiver_add (struct cap_flow *flow, struct cap_receiver *recv, void *buf)
{
  recv->thread = thread_self ();
  recv->buf = buf;
  recv->spurious = false;
  memset (&recv->mdata, 0, sizeof (recv->mdata));
  list_insert_tail (&flow->receivers, &recv->lnode);
}

static void
cap_recv_wakeup_fast (struct cap_flow *flow)
{
  if (list_empty (&flow->receivers))
    return;

  _Auto recv = list_pop (&flow->receivers, struct cap_receiver, lnode);
  recv->spurious = true;
  thread_wakeup (recv->thread);
}

static struct cap_alert*
cap_recv_pop_alert (struct cap_flow *flow, void *buf, uint32_t flags,
                    struct ipc_msg_data *mdata, int *outp,
                    struct spinlock_guard *guard)
{
  if (!pqueue_empty (&flow->pending_alerts))
    return (pqueue_pop_entry (&flow->pending_alerts, struct cap_alert, pnode));
  else if (flags & CAP_ALERT_NONBLOCK)
    {
      cap_flow_guard_fini (guard);
      *outp = EAGAIN;
      return (NULL);
    }

  struct cap_receiver recv;
  cap_receiver_add (flow, &recv, buf);

  do
    thread_sleep (&flow->lock, flow, "flow-alert");
  while (pqueue_empty (&flow->pending_alerts));

  if (recv.spurious)
    return (pqueue_pop_entry (&flow->pending_alerts, struct cap_alert, pnode));

  cap_flow_guard_fini (guard);
  if (recv.mdata.bytes_recv >= 0 && mdata)
    {
      recv.mdata.bytes_recv = CAP_ALERT_SIZE;
      user_copy_to (mdata, &recv.mdata, sizeof (*mdata));
    }

  *outp = recv.mdata.bytes_recv >= 0 ? 0 : (int)-recv.mdata.bytes_recv;
  return (NULL);
}

int
cap_recv_alert (struct cap_flow *flow, void *buf,
                uint32_t flags, struct ipc_msg_data *mdata)
{
  uint32_t ids[2] = { 0, 0 };
  uintptr_t tag = 0;
  _Auto guard = cap_flow_guard_make (flow);

  int error;
  _Auto entry = cap_recv_pop_alert (flow, buf, flags, mdata, &error, &guard);

  if (! entry)
    return (error);

  void *payload = entry->payload;
  int type = cap_alert_type (entry);

  if (type == CAP_ALERT_INTR)
    { // Copy into a temp buffer so we may reset the counter.
      payload = alloca (sizeof (entry->k_alert));
      *(struct cap_kern_alert *)payload = entry->k_alert;
      entry->k_alert.intr.count = 0;
    }
  else if (type != CAP_ALERT_USER)
    hlist_remove (&entry->hnode);
  else
    {
      ids[0] = entry->task_id;
      ids[1] = entry->thread_id;
      tag = entry->tag;
    }

  pqueue_inc (&flow->pending_alerts, 1 << 8);
  cap_flow_guard_fini (&guard);

  if (unlikely (user_copy_to (buf, payload, CAP_ALERT_SIZE) != 0))
    {
      cap_flow_guard_lock (&guard);
      pqueue_insert (&flow->pending_alerts, &entry->pnode);

      if (type == CAP_ALERT_INTR)
        entry->k_alert.intr.count +=
          ((struct cap_kern_alert *)payload)->intr.count;
      else if (type != CAP_ALERT_USER)
        hlist_insert_head (&flow->alloc_alerts, &entry->hnode);

      cap_recv_wakeup_fast (flow);
      cap_flow_guard_fini (&guard);
      return (EFAULT);
    }
  else if (mdata)
    {
      struct ipc_msg_data tmp;
      memset (&tmp, 0, sizeof (tmp));

      tmp.bytes_recv = CAP_ALERT_SIZE;
      tmp.tag = tag;
      tmp.task_id = ids[0], tmp.thread_id = ids[1];
      user_copy_to (mdata, &tmp, sizeof (tmp));
    }

  return (0);
}

static void
cap_fill_ids (int *thr_idp, int *task_idp, struct thread *thr)
{
  *thr_idp = thread_id (thr);
  *task_idp = task_id (thr->task);
}

int
(cap_send_alert) (struct cap_base *cap, const void *buf,
                  uint32_t flags, uint32_t prio)
{
  struct cap_flow *flow;
  uintptr_t tag;

  switch (cap_type (cap))
    {
      case CAP_TYPE_CHANNEL:
        flow = ((struct cap_channel *)cap)->flow;
        tag = ((struct cap_channel *)cap)->tag;
        break;

      case CAP_TYPE_FLOW:
        flow = (struct cap_flow *)cap;
        tag = flow->tag;
        break;

      default:
        return (EBADF);
    }

  /*
   * Copy into a temporary buffer, since the code below may otherwise
   * generate a page fault while holding a spinlock.
   */
  char abuf[CAP_ALERT_SIZE] = { 0 };
  if (user_copy_from (abuf, buf, CAP_ALERT_SIZE) != 0)
    return (EFAULT);

  struct cap_receiver *recv;

  {
    CLEANUP (cap_flow_guard_fini) _Auto guard = cap_flow_guard_make (flow);
    if (list_empty (&flow->receivers))
      {
        _Auto alert = cap_flow_alloc_alert (&guard, flags);
        if (! alert)
          return (ENOMEM);

        memcpy (alert->payload, abuf, CAP_ALERT_SIZE);
        cap_alert_init_nodes (alert, CAP_ALERT_USER, prio);
        pqueue_insert (&flow->pending_alerts, &alert->pnode);
        cap_fill_ids (&alert->thread_id, &alert->task_id, thread_self ());
        alert->tag = tag;

        /*
         * Allocating an alert temporarily drops the flow lock. Since a
         * receiver could have been added in the meantime, we need to
         * check again before returning.
         */
        cap_recv_wakeup_fast (flow);
        return (0);
      }

    recv = list_pop (&flow->receivers, typeof (*recv), lnode);
  }

  cap_fill_ids (&recv->mdata.thread_id, &recv->mdata.task_id, thread_self ());
  recv->mdata.tag = tag;
  ssize_t rv = ipc_bcopy (recv->thread->task, recv->buf, sizeof (abuf),
                          abuf, sizeof (abuf), IPC_COPY_TO | IPC_CHECK_REMOTE);

  thread_wakeup (recv->thread);
  recv->mdata.bytes_recv = rv;
  return (rv < 0 ? (int)-rv : 0);
}

static void
cap_task_swap (struct task **taskp, struct thread *self)
{
  cpu_flags_t flags;
  thread_preempt_disable_intr_save (&flags);

  struct task *xtask = self->xtask;
  self->xtask = *taskp;
  *taskp = xtask;

  pmap_load (self->xtask->map->pmap);
  thread_preempt_enable_intr_restore (flags);
}

static void
cap_ipc_msg_data_init (struct ipc_msg_data *data, uintptr_t tag)
{
  data->size = sizeof (*data);
  data->tag = tag;
  data->bytes_recv = data->bytes_sent = 0;
  data->flags = 0;
  data->vmes_sent = data->caps_sent = 0;
  data->vmes_recv = data->caps_recv = 0;
}

static void
cap_flow_push_lpad (struct cap_flow *flow, struct cap_lpad *lpad)
{
  CAP_FLOW_GUARD (flow);
  slist_insert_head (&flow->lpads, &lpad->snode);

  if (list_empty (&flow->waiters))
    return;

  _Auto sender = list_first_entry (&flow->waiters, struct cap_sender, lnode);
  thread_wakeup (sender->thread);
}

static struct cap_lpad*
cap_pop_lpad (struct cap_flow *flow, struct thread *self)
{
  CAP_FLOW_GUARD (flow);
  if (slist_empty (&flow->lpads))
    {
      struct cap_sender sender = { .thread = self };
      list_insert_tail (&flow->waiters, &sender.lnode);

      do
        thread_sleep (&flow->lock, flow, "flow-sender");
      while (slist_empty (&flow->lpads));

      list_remove (&sender.lnode);
    }

  _Auto lpad = slist_first_entry (&flow->lpads, struct cap_lpad, snode);
  slist_remove (&flow->lpads, NULL);
  return (lpad);
}

#define CAP_MSG_MASK        (IPC_MSG_TRUNC | IPC_MSG_ERROR | IPC_MSG_KERNEL)
#define CAP_MSG_REQ_PAGES   0x1000

static_assert ((CAP_MSG_REQ_PAGES & CAP_MSG_MASK) == 0,
               "CAP_MSG_REQ_PAGES must not intersect message mask");

static ssize_t
cap_sender_impl (struct cap_flow *flow, uintptr_t tag, struct cap_iters *in,
                 struct cap_iters *out, struct ipc_msg_data *data,
                 uint32_t xflags, struct cap_base *src)
{
  struct thread *self = thread_self ();
  _Auto lpad = cap_pop_lpad (flow, self);
  uint32_t dirf = IPC_COPY_TO | IPC_CHECK_REMOTE |
                  ((xflags & IPC_MSG_KERNEL) ? 0 : IPC_CHECK_LOCAL);

  cap_ipc_msg_data_init (&lpad->mdata, tag);
  ssize_t nb = cap_transfer_iters (lpad->task, &lpad->in_it, in,
                                   dirf, &lpad->mdata.bytes_recv);

  lpad->mdata.flags |= (xflags & CAP_MSG_MASK) | (nb < 0 ? IPC_MSG_ERROR : 0);
  lpad->cur_in = in;
  lpad->cur_out = out;
  lpad->xflags = xflags & ~CAP_MSG_MASK;

  struct cap_lpad *cur_lpad = self->cur_lpad;
  self->cur_lpad = lpad;
  cap_fill_ids (&lpad->mdata.thread_id, &lpad->mdata.task_id, self);
  lpad->src = src;

  // Switch task (also sets the pmap).
  cap_task_swap (&lpad->task, self);
  user_copy_to ((void *)lpad->ctx[2], &lpad->mdata, sizeof (lpad->mdata));

  // Jump to new PC and SP.
  uintptr_t prev_stack = *lpad->ctx;
  ssize_t ret = cpu_lpad_swap (lpad->ctx, cur_lpad, (void *)flow->entry);

  // We're back.
  *lpad->ctx = prev_stack;
  if (data && user_copy_to (data, &lpad->mdata, sizeof (*data)) != 0)
    ret = -EFAULT;

  cap_flow_push_lpad (flow, lpad);
  self->cur_lpad = cur_lpad;
  return (ret);
}

ssize_t
cap_send_iters (struct cap_base *cap, struct cap_iters *in,
                struct cap_iters *out, struct ipc_msg_data *data,
                uint32_t xflags)
{
  struct cap_flow *flow;
  uintptr_t tag;
  struct ipc_msg_data mdata;

  if (! cap)
    return (-EBADF);

  switch (cap_type (cap))
    {
      case CAP_TYPE_FLOW:
        flow = (struct cap_flow *)cap;
        tag = flow->tag;
        break;

      case CAP_TYPE_CHANNEL:
        flow = ((struct cap_channel *)cap)->flow;
        tag = ((struct cap_channel *)cap)->tag;
        break;

      case CAP_TYPE_THREAD:
        return (thread_handle_msg (((struct cap_thread *)cap)->thread,
                                   in, out, &mdata));
      case CAP_TYPE_TASK:
        return (task_handle_msg (((struct cap_task *)cap)->task,
                                 in, out, &mdata));

      case CAP_TYPE_KERNEL:
        // TODO: Implement.
      default:
        return (-EINVAL);
    }

  return (cap_sender_impl (flow, tag, in, out, data, xflags, cap));
}

ssize_t
cap_pull_iters (struct cap_iters *it, struct ipc_msg_data *mdata)
{
  struct cap_lpad *lpad = thread_self()->cur_lpad;
  if (! lpad)
    return (-EINVAL);

  struct ipc_msg_data tmp;
  cap_ipc_msg_data_init (&tmp, lpad->mdata.tag);

  ssize_t ret = cap_transfer_iters (lpad->task, lpad->cur_in, it,
                                    IPC_COPY_FROM | IPC_CHECK_BOTH,
                                    &tmp.bytes_recv);

  lpad->mdata.bytes_recv += tmp.bytes_recv;
  lpad->mdata.vmes_recv += tmp.vmes_recv;
  lpad->mdata.caps_recv += tmp.caps_recv;

  if (mdata)
    user_copy_to (mdata, &tmp, sizeof (tmp));

  return (ret);
}

ssize_t
cap_push_iters (struct cap_iters *it, struct ipc_msg_data *mdata)
{
  struct cap_lpad *lpad = thread_self()->cur_lpad;
  if (! lpad)
    return (-EINVAL);

  struct ipc_msg_data tmp;
  cap_ipc_msg_data_init (&tmp, lpad->mdata.tag);

  ssize_t ret = cap_transfer_iters (lpad->task, lpad->cur_out, it,
                                    IPC_COPY_TO | IPC_CHECK_BOTH,
                                    &tmp.bytes_sent);

  lpad->mdata.bytes_sent += tmp.bytes_sent;
  lpad->mdata.vmes_sent += tmp.vmes_sent;
  lpad->mdata.caps_sent += tmp.caps_sent;

  if (mdata)
    user_copy_to (mdata, &tmp, sizeof (tmp));

  return (ret);
}

static void
cap_mdata_swap (struct ipc_msg_data *mdata)
{
  SWAP (&mdata->bytes_sent, &mdata->bytes_recv);
  SWAP (&mdata->caps_sent, &mdata->caps_recv);
  SWAP (&mdata->vmes_sent, &mdata->vmes_recv);
}

static void
cap_lpad_iters_reset (struct cap_lpad *lpad)
{
#define cap_reset_iter(name)   \
  ipc_##name##_iter_init (&lpad->in_it.name, lpad->in_it.name.begin,   \
                          lpad->in_it.name.end)
  cap_reset_iter (iov);
  cap_reset_iter (cap);
  cap_reset_iter (vme);

#undef cap_reset_iter

  lpad->in_it.iov.cur = lpad->nr_cached_iovs;
  lpad->in_it.iov.cache_idx = IPC_IOV_ITER_CACHE_SIZE - lpad->nr_cached_iovs;
}

noreturn static void
cap_lpad_return (struct cap_lpad *lpad, struct thread *self, ssize_t rv)
{
  cap_lpad_iters_reset (lpad);
  cap_task_swap (&lpad->task, self);
  cpu_lpad_return (lpad->ctx[0], rv);
}

ssize_t
cap_reply_iters (struct cap_iters *it, int rv)
{
  struct thread *self = thread_self ();
  struct cap_lpad *lpad = self->cur_lpad;
  ssize_t ret;

  if (!lpad || lpad->xflags)
    return (-EINVAL);
  else if (rv >= 0)
    {
      ret = cap_transfer_iters (lpad->task, lpad->cur_out, it,
                                IPC_COPY_TO | IPC_CHECK_BOTH,
                                &lpad->mdata.bytes_sent);
      if (ret > 0)
        ret = lpad->mdata.bytes_sent;

      cap_mdata_swap (&lpad->mdata);
      if (!ipc_iov_iter_empty (&it->iov) ||
          ipc_vme_iter_size (&it->vme) ||
          ipc_cap_iter_size (&it->cap))
        lpad->mdata.flags |= IPC_MSG_TRUNC;
    }
  else
    ret = rv;

  cap_lpad_return (lpad, self, ret);
}

static void
cap_lpad_fill_cache (struct cap_lpad *lpad, struct ipc_msg *msg)
{
  uint32_t nmax = MIN (msg->iov_cnt, IPC_IOV_ITER_CACHE_SIZE);
  _Auto outv = lpad->in_it.iov.cache + IPC_IOV_ITER_CACHE_SIZE;

  if (likely (user_copy_from (outv - nmax, msg->iovs,
                              nmax * sizeof (*outv)) == 0))
    {
      lpad->in_it.iov.cur += nmax;
      lpad->in_it.iov.cache_idx = IPC_IOV_ITER_CACHE_SIZE - nmax;
      lpad->nr_cached_iovs = nmax;
    }
}

int
cap_flow_add_lpad (struct cap_flow *flow, void *stack, size_t size,
                   struct ipc_msg *msg, struct ipc_msg_data *mdata,
                   struct cap_thread_info *info __unused)
{
  /*
   * TODO: The user check for the stack can't be made here (yet),
   * as the tests run with blocks that reside in kernel space.
   */
  struct cap_lpad *entry = kmem_cache_alloc (&cap_lpad_cache);
  if (! entry)
    return (ENOMEM);

  entry->size = size;
  entry->ctx[0] = (uintptr_t)stack;
  entry->ctx[1] = (uintptr_t)msg;
  entry->ctx[2] = (uintptr_t)mdata;
  memset (&entry->mdata, 0, sizeof (entry->mdata));
  cap_iters_init_msg (&entry->in_it, msg);
  cap_lpad_fill_cache (entry, msg);
  task_ref (entry->task = task_self ());

  cap_flow_push_lpad (flow, entry);
  return (0);
}

int
cap_flow_rem_lpad (struct cap_flow *flow, uintptr_t stack, bool unmap)
{
  _Auto guard = cap_flow_guard_make (flow);
  struct cap_lpad *entry;
  struct slist_node *prev = NULL;

  slist_for_each_entry (&flow->lpads, entry, snode)
    {
      if (entry->task == task_self () &&
          (stack == ~(uintptr_t)0 || stack == entry->ctx[0]))
        break;

      prev = &entry->snode;
    }

  if (! entry)
    {
      cap_flow_guard_fini (&guard);
      return (ESRCH);
    }

  slist_remove (&flow->lpads, prev);
  cap_flow_guard_fini (&guard);

  int error = stack != ~(uintptr_t)0 || !unmap ? 0 :
              vm_map_remove (vm_map_self (), stack, entry->size);

  if (! error)
    kmem_cache_free (&cap_lpad_cache, entry);
  else
    cap_flow_push_lpad (flow, entry);

  return (error);
}

static int
cap_handle_intr (void *arg)
{
  struct list *list = arg;
  assert (list >= &cap_intr_handlers[0] &&
          list <= &cap_intr_handlers[ARRAY_SIZE (cap_intr_handlers) - 1]);

  RCU_GUARD ();
  list_rcu_for_each (list, tmp)
    {
      _Auto alert = list_entry (tmp, struct cap_alert_async, xlink);
      SPINLOCK_GUARD (&alert->flow->lock);
      if (++alert->base.k_alert.intr.count == 1)
        {
          pqueue_insert (&alert->flow->pending_alerts, &alert->base.pnode);
          cap_recv_wakeup_fast (alert->flow);
        }
    }

  return (EAGAIN);
}

static int
cap_intr_add (uint32_t intr, struct list *node)
{
  assert (intr >= CPU_EXC_INTR_FIRST &&
          intr - CPU_EXC_INTR_FIRST < ARRAY_SIZE (cap_intr_handlers));
  struct list *list = &cap_intr_handlers[intr - CPU_EXC_INTR_FIRST];
  ADAPTIVE_LOCK_GUARD (&cap_intr_lock);

  if (list_empty (list))
    {
      CPU_INTR_GUARD ();

      int error = intr_register (intr, cap_handle_intr, list);
      if (error)
        return (error);

      list_rcu_insert_head (list, node);
      return (0);
    }

  list_rcu_insert_head (list, node);
  return (0);
}

static void
cap_intr_rem (uint32_t intr, struct list *node)
{
  ADAPTIVE_LOCK_GUARD (&cap_intr_lock);
  list_rcu_remove (node);
  if (list_empty (&cap_intr_handlers[intr - CPU_EXC_INTR_FIRST]))
    intr_unregister (intr, cap_handle_intr);
}

static struct cap_alert_async*
cap_alert_async_find (struct cap_flow *flow, int type, int id)
{
  struct cap_alert *tmp;
  hlist_for_each_entry (&flow->alloc_alerts, tmp, hnode)
    if (cap_alert_type (tmp) == type && tmp->k_alert.any_id == id)
      return ((void *)tmp);

  return (NULL);
}

int
cap_intr_register (struct cap_flow *flow, uint32_t irq)
{
  if (irq < CPU_EXC_INTR_FIRST || irq > CPU_EXC_INTR_LAST)
    return (EINVAL);

  struct cap_alert_async *ap = kmem_cache_alloc (&cap_misc_cache);
  if (! ap)
    return (ENOMEM);

  cap_alert_init_nodes (&ap->base, CAP_ALERT_INTR, CAP_ALERT_INTR_PRIO);
  list_node_init (&ap->xlink);
  ap->flow = flow;
  ap->base.k_alert.type = CAP_ALERT_INTR;
  ap->base.k_alert.intr.irq = irq;
  ap->base.k_alert.intr.count = 0;

  int error = cap_intr_add (irq, &ap->xlink);
  if (error)
    {
      kmem_cache_free (&cap_misc_cache, ap);
      return (error);
    }

  _Auto guard = cap_flow_guard_make (flow);
  if (unlikely (cap_alert_async_find (flow, CAP_ALERT_INTR, irq)))
    {
      cap_flow_guard_fini (&guard);
      cap_intr_rem (irq, &ap->xlink);
      rcu_wait ();
      kmem_cache_free (&cap_misc_cache, ap);
      return (EALREADY);
    }

  hlist_insert_head (&flow->alloc_alerts, &ap->base.hnode);
  cap_flow_guard_fini (&guard);
  return (0);
}

static int
cap_unregister_impl (struct cap_flow *flow, int type,
                     uint32_t id, struct cap_alert_async **outp)
{
  CAP_FLOW_GUARD (flow);
  _Auto entry = cap_alert_async_find (flow, type, id);

  if (! entry)
    return (ESRCH);

  hlist_remove (&entry->base.hnode);
  if (!pqueue_node_unlinked (&entry->base.pnode))
    pqueue_remove (&flow->pending_alerts, &entry->base.pnode);

  *outp = entry;
  return (0);
}

int
cap_intr_unregister (struct cap_flow *flow, uint32_t irq)
{
  cpu_flags_t flags;
  struct cap_alert_async *entry;

  cpu_intr_save (&flags);
  int error = cap_unregister_impl (flow, CAP_ALERT_INTR, irq, &entry);

  if (! error)
    {
      cap_intr_rem (irq, &entry->xlink);
      cpu_intr_restore (flags);
      rcu_wait ();
      kmem_cache_free (&cap_misc_cache, entry);
    }
  else
    cpu_intr_restore (flags);

  return (error);
}

static int
cap_register_task_thread (struct cap_flow *flow, struct kuid_head *kuid,
                          uint32_t prio, int type, struct bulletin *outp)
{
  struct cap_alert_async *ap = kmem_cache_alloc (&cap_misc_cache);
  if (! ap)
    return (ENOMEM);

  cap_alert_init_nodes (&ap->base, type, prio);
  list_node_init (&ap->xlink);
  ap->flow = flow;
  ap->base.k_alert.type = type;
  ap->base.k_alert.any_id = kuid->id;

  _Auto guard = cap_flow_guard_make (flow);
  if (unlikely (cap_alert_async_find (flow, type, kuid->id)))
    {
      cap_flow_guard_fini (&guard);
      kmem_cache_free (&cap_misc_cache, ap);
      return (EALREADY);
    }

  hlist_insert_head (&flow->alloc_alerts, &ap->base.hnode);
  spinlock_lock (&outp->lock);
  list_insert_tail (&outp->subs, &ap->xlink);
  spinlock_unlock (&outp->lock);
  cap_flow_guard_fini (&guard);
  return (0);
}

static int
cap_task_thread_unregister (struct cap_flow *flow, int type,
                            int tid, struct bulletin *outp)
{
  struct cap_alert_async *entry;
  int error = cap_unregister_impl (flow, type, tid, &entry);

  if (error)
    return (error);

  spinlock_lock (&outp->lock);
  list_remove (&entry->xlink);
  spinlock_unlock (&outp->lock);
  kmem_cache_free (&cap_misc_cache, entry);
  return (0);
}

int
cap_thread_register (struct cap_flow *flow, struct thread *thr)
{
  if (! thr)
    return (EINVAL);

  return (cap_register_task_thread (flow, &thr->kuid, CAP_ALERT_THREAD_PRIO,
                                    CAP_ALERT_THREAD_DIED, &thr->dead_subs));
}

int
cap_task_register (struct cap_flow *flow, struct task *task)
{
  if (! task)
    return (EINVAL);

  return (cap_register_task_thread (flow, &task->kuid, CAP_ALERT_TASK_PRIO,
                                    CAP_ALERT_TASK_DIED, &task->dead_subs));
}

int
cap_thread_unregister (struct cap_flow *flow, struct thread *thr)
{
  if (! thr)
    return (EINVAL);

  return (cap_task_thread_unregister (flow, CAP_ALERT_THREAD_DIED,
                                      thread_id (thr), &thr->dead_subs));
}

int
cap_task_unregister (struct cap_flow *flow, struct task *task)
{
  if (! task)
    return (EINVAL);

  return (cap_task_thread_unregister (flow, CAP_ALERT_TASK_DIED,
                                      task_id (task), &task->dead_subs));
}

void
cap_notify_dead (struct bulletin *bulletin)
{
  struct list dead_subs;

  spinlock_lock (&bulletin->lock);
  list_set_head (&dead_subs, &bulletin->subs);
  list_init (&bulletin->subs);
  spinlock_unlock (&bulletin->lock);

  struct cap_alert_async *ap;
  list_for_each_entry (&dead_subs, ap, xlink)
    {
      _Auto flow = ap->flow;

      CAP_FLOW_GUARD (flow);
      if (!pqueue_node_unlinked (&ap->base.pnode))
        continue;

      pqueue_insert (&flow->pending_alerts, &ap->base.pnode);
      cap_recv_wakeup_fast (flow);
    }
}

int
(cap_intern) (struct cap_base *cap, uint32_t flags)
{
  return (cap ? cspace_add_free (cspace_self (), cap, flags) : -EINVAL);
}

ssize_t
cap_request_pages (struct cap_channel *chp, uint64_t off,
                   uint32_t nr_pages, struct vm_page **pages)
{
  struct kmessage msg;
  msg.type = KMSG_TYPE_PAGE_REQ;
  msg.msg_flags = 0;
  msg.page_req.start = off;
  msg.page_req.end = off + nr_pages * PAGE_SIZE;

  struct cap_iters in, out;

  cap_iters_init_buf (&in, &msg, sizeof (msg));
  cap_iters_init_buf (&out, pages, nr_pages * sizeof (**pages));

  return (cap_send_iters (CAP (chp), &in, &out, NULL,
                          IPC_MSG_KERNEL | CAP_MSG_REQ_PAGES));
}

ssize_t
cap_reply_pagereq (const uintptr_t *usrc, uint32_t cnt)
{
  _Auto self = thread_self ();
  struct cap_lpad *lpad = self->cur_lpad;

  if (!lpad || !(lpad->xflags & CAP_MSG_REQ_PAGES))
    return (-EINVAL);

  uint32_t npg = lpad->cur_out->iov.head.iov_len / sizeof (struct vm_page);
  if (npg < cnt)
    cnt = npg;

  assert (cnt <= VM_MAP_MAX_FRAMES);
  uintptr_t src[VM_MAP_MAX_FRAMES];
  if (user_copy_from (src, usrc, cnt * sizeof (*usrc)) != 0)
    return (-EFAULT);

  struct vm_page **pages = lpad->cur_out->iov.head.iov_base;
  int rv = vm_map_reply_pagereq (src, cnt, pages);

  if (rv < 0)
    return (rv);

  cap_lpad_return (lpad, self, rv);
}

static struct vm_object*
cap_channel_load_vmobj (struct cap_channel *chp)
{
  RCU_GUARD ();
  _Auto prev = atomic_load_rlx (&chp->vmobj);
  return (!prev || vm_object_tryref (prev) ? prev : NULL);
}

struct vm_object*
cap_channel_get_vmobj (struct cap_channel *chp)
{
  uint32_t flags = VM_OBJECT_EXTERNAL |
                   ((chp->flow->base.tflags & CAP_FLOW_PAGER_FLUSHES) ?
                    VM_OBJECT_FLUSHES : 0);
  while (1)
    {
      _Auto prev = cap_channel_load_vmobj (chp);
      if (prev)
        return (prev);

      struct vm_object *obj;
      if (vm_object_create (&obj, flags, chp) != 0)
        // We couldn't create the object but maybe someone else could.
        return (cap_channel_load_vmobj (chp));
      else if (atomic_cas_bool_acq (&chp->vmobj, NULL, obj))
        {
          cap_base_acq (chp);
          return (obj);
        }

      vm_object_destroy (obj);
    }
}

void
cap_channel_put_vmobj (struct cap_channel *chp)
{
  rcu_read_enter ();
  _Auto prev = atomic_load_rlx (&chp->vmobj);
  if (prev && vm_object_unref_nofree (prev, 1))
    {
      atomic_store_rel (&chp->vmobj, NULL);
      rcu_read_leave ();
      vm_object_destroy (prev);
    }
  else
    rcu_read_leave ();
}

bool
cap_channel_mark_shared (struct cap_base *cap)
{
  while (1)
    {
      uintptr_t tmp = atomic_load_rlx (&cap->tflags);
      if (tmp & CAP_CHANNEL_SHARED)
        return (false);
      else if (atomic_cas_bool_acq_rel (&cap->tflags, tmp,
                                        tmp | CAP_CHANNEL_SHARED))
        return (true);

      atomic_spin_nop ();
    }
}

static size_t
cap_get_max (const size_t *args, size_t n)
{
  size_t ret = *args;
  for (size_t i = 1; i < n; ++i)
    if (args[i] > ret)
      ret = args[i];

  return (ret);
}

#define CAP_MAX(...)   \
  ({   \
     const size_t args_[] = { __VA_ARGS__ };   \
     cap_get_max (args_, ARRAY_SIZE (args_));   \
   })

static int __init
cap_setup (void)
{
  // Every capability type but flows are allocated from the same cache.
#define SZ(type)   sizeof (struct cap_##type)
#define AL(type)   alignof (struct cap_##type)

  size_t size = CAP_MAX (SZ (task), SZ (thread), SZ (channel),
                         SZ (kernel), SZ (alert_async));
  size_t alignment = CAP_MAX (AL (task), AL (thread), AL (channel),
                              AL (kernel), AL (alert_async));

  kmem_cache_init (&cap_misc_cache, "cap_misc", size, alignment, NULL, 0);
  kmem_cache_init (&cap_flow_cache, "cap_flow",
                   sizeof (struct cap_flow), 0, NULL, 0);
  kmem_cache_init (&cap_lpad_cache, "cap_lpad",
                   sizeof (struct cap_lpad), 0, NULL, 0);

  adaptive_lock_init (&cap_intr_lock);
  for (size_t i = 0; i < ARRAY_SIZE (cap_intr_handlers); ++i)
    list_init (&cap_intr_handlers[i]);

  return (0);
}

INIT_OP_DEFINE (cap_setup,
                INIT_OP_DEP (intr_setup, true),
                INIT_OP_DEP (kmem_setup, true));

#ifdef CONFIG_SHELL

static void
cap_shell_info (struct shell *shell, int argc, char **argv)
{
  _Auto stream = shell->stream;
  if (argc < 2)
    {
      stream_puts (stream, "usage: cap_info task\n");
      return;
    }

  const _Auto task = task_lookup (argv[1]);
  if (! task)
    {
      stream_puts (stream, "cap_info: task not found\n");
      return;
    }

  fmt_xprintf (stream, "capabilities:\nindex\ttype\textra\n");
  ADAPTIVE_LOCK_GUARD (&task->caps.lock);

  struct rdxtree_iter it;
  struct cap_base *cap;

  rdxtree_for_each (&task->caps.tree, &it, cap)
    {
      fmt_xprintf (stream, "%llu\t", it.key);
      switch (cap_type (cap))
        {
          case CAP_TYPE_CHANNEL:
            fmt_xprintf (stream, "channel\t{tag: %lu}\n",
                         ((struct cap_channel *)cap)->tag);
            break;
          case CAP_TYPE_FLOW:
            fmt_xprintf (stream, "flow\t{entry: %lu}\n",
                         ((struct cap_flow *)cap)->entry);
            break;
          case CAP_TYPE_TASK:
            fmt_xprintf (stream, "task\t{task: %s}\n",
                         ((struct cap_task *)cap)->task->name);
            break;
          case CAP_TYPE_THREAD:
            fmt_xprintf (stream, "thread\t{thread: %s}\n",
                         ((struct cap_thread *)cap)->thread->name);
            break;
          case CAP_TYPE_KERNEL:
            fmt_xprintf (stream, "kernel\t{kind: %d}\n",
                         ((struct cap_kernel *)cap)->kind);
            break;
          default:
            panic ("unknown capability type: %u\n", cap_type (cap));
        }
    }

  task_unref (task);
}

static struct shell_cmd cap_shell_cmds[] =
{
  SHELL_CMD_INITIALIZER ("cap_info", cap_shell_info,
                         "cap_info <task_name>",
                         "display capabilities of a task"),
};

static int __init
cap_setup_shell (void)
{
  SHELL_REGISTER_CMDS (cap_shell_cmds, shell_get_main_cmd_set ());
  return (0);
}

INIT_OP_DEFINE (cap_setup_shell,
                INIT_OP_DEP (printf_setup, true),
                INIT_OP_DEP (shell_setup, true),
                INIT_OP_DEP (task_setup, true),
                INIT_OP_DEP (cap_setup, true));

#endif
