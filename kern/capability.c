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
#include <kern/rcu.h>
#include <kern/thread.h>
#include <kern/user.h>

#include <machine/pmap.h>

#include <stdio.h>

struct cap_alert
{
  union
    {
      struct
        { // Valid for user alerts and when not pending.
          int task_id;
          int thread_id;
        };

      struct slist_node snode;
    };

  struct plist_node pnode;
  union
    {
      char payload[CAP_ALERT_SIZE + 1];
      struct cap_kern_alert k_alert;
    };
};

struct cap_alert_async
{
  struct cap_alert base;
  struct list xlink;
  struct cap_flow *flow;
};

#define cap_alert_type(alert)   ((alert)->payload[CAP_ALERT_SIZE])

struct cap_port_entry
{
  struct slist_node snode;
  struct task *task;
  size_t size;
  uintptr_t ctx[3];   // SP and function arguments.
  struct ipc_msg_data mdata;
  struct cap_iters in_it;
  struct cap_iters *out_it;
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

static struct kmem_cache cap_flow_cache;
static struct kmem_cache cap_misc_cache;
static struct kmem_cache cap_port_cache;

static struct list cap_intr_handlers[CPU_INTR_TABLE_SIZE];
static struct adaptive_lock cap_intr_lock;

#define CAP_FROM_SREF(ptr, type)   structof (ptr, type, base.sref)

static void
cap_base_init (struct cap_base *base, unsigned int type, sref_noref_fn_t noref)
{
  assert (type < CAP_TYPE_MAX);
  base->type = type;
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

static void
cap_channel_fini (struct sref_counter *sref)
{
  _Auto chp = CAP_FROM_SREF (sref, struct cap_channel);
  cap_base_rel (chp->flow);
  kmem_cache_free (&cap_misc_cache, chp);
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
  *outp = ret;
  return (0);
}

static int cap_intr_rem (uint32_t irq, struct list *link);

static void
cap_alert_free (struct cap_alert *alert)
{
  _Auto async = (struct cap_alert_async *)alert;
  _Auto k_alert = &alert->k_alert;

  switch (cap_alert_type (alert))
    {
      case CAP_ALERT_USER:
        kmem_free (alert, sizeof (*alert));
        break;

      case CAP_ALERT_INTR:
        cap_intr_rem (k_alert->intr.irq, &async->xlink);
        break;

      default:
        // XXX: Implement.
        break;
    }
}

static void
cap_flow_fini (struct sref_counter *sref)
{
  _Auto flow = CAP_FROM_SREF (sref, struct cap_flow);

  struct cap_alert *alert, *tmp;
  plist_for_each_entry_safe (&flow->pending_alerts, alert, tmp, pnode)
    if (cap_alert_type (alert) == CAP_ALERT_USER)
      kmem_free (alert, sizeof (*alert));

  slist_for_each_entry_safe (&flow->alloc_alerts, alert, tmp, snode)
    cap_alert_free (alert);

  struct cap_port_entry *port, *gt;
  slist_for_each_entry_safe (&flow->lpads, port, gt, snode)
    {
      task_unref (port->task);
      kmem_cache_free (&cap_port_cache, port);
    }

  kmem_cache_free (&cap_flow_cache, flow);
}

int
cap_flow_create (struct cap_flow **outp, uint32_t flags,
                 uintptr_t tag, uintptr_t entry)
{
  struct cap_flow *ret = kmem_cache_alloc (&cap_flow_cache);
  if (! ret)
    return (ENOMEM);

  cap_base_init (&ret->base, CAP_TYPE_FLOW, cap_flow_fini);
  spinlock_init (&ret->lock);
  list_init (&ret->waiters);
  list_init (&ret->receivers);
  slist_init (&ret->lpads);
  slist_init (&ret->alloc_alerts);
  plist_init (&ret->pending_alerts);
  ret->flags = flags;
  ret->tag = tag;
  ret->entry = entry;

  *outp = ret;
  return (0);
}

/*
 * Attempt to set the tag to a new value. The only valid transition is
 * from zero to any value.
 */

static int
cap_cas_tag (uintptr_t *tagp, uintptr_t value)
{
  while (1)
    {
      uintptr_t tmp = atomic_load_rlx (tagp);
      if (tmp != 0)
        return (EEXIST);
      else if (atomic_cas_bool_rlx (tagp, tmp, value))
        return (0);

      cpu_pause ();
    }
}

int
(cap_set_tag) (struct cap_base *cap, uintptr_t tag)
{
  if (! tag)
    return (EINVAL);
  else if (cap->type == CAP_TYPE_CHANNEL)
    return (cap_cas_tag (&((struct cap_channel *)cap)->tag, tag));
  else if (cap->type == CAP_TYPE_FLOW)
    return (cap_cas_tag (&((struct cap_flow *)cap)->tag, tag));

  return (EINVAL);
}

int
(cap_get_tag) (const struct cap_base *cap, uintptr_t *tagp)
{
  if (cap->type == CAP_TYPE_CHANNEL)
    *tagp = ((const struct cap_channel *)cap)->tag;
  else if (cap->type == CAP_TYPE_FLOW)
    *tagp = ((const struct cap_flow *)cap)->tag;
  else
    return (EINVAL);

  return (0);
}

int
cap_channel_link (struct cap_channel *channel, struct cap_flow *flow)
{
  while (1)
    {
      _Auto prev = atomic_load_rlx (&channel->flow);
      if (prev && flow)
        return (EAGAIN);
      else if (atomic_cas_bool_acq (&channel->flow, prev, flow))
        return (0);

      cpu_pause ();
    }
}

int
cap_flow_hook (struct cap_channel **outp, struct task *task, int capx)
{
  struct cap_base *base = cspace_get (&task->caps, capx);
  if (! base)
    return (EBADF);
  else if (base->type != CAP_TYPE_FLOW)
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
                    struct cap_iters *l_it, int dir, struct ipc_msg_data *data)
{
  ssize_t ret = ipc_iov_iter_copy (task, &r_it->iov, &l_it->iov, dir);
  if (ret < 0)
    return (ret);

  data->nbytes += ret;
  if (ipc_cap_iter_size (&r_it->cap) && ipc_cap_iter_size (&l_it->cap))
    {
      int nr_caps = ipc_cap_iter_copy (task, &r_it->cap, &l_it->cap, dir);
      if (nr_caps < 0)
        return (nr_caps);

      data->caps_recv += nr_caps;
    }

  if (ipc_page_iter_size (&r_it->page) && ipc_page_iter_size (&l_it->page))
    {
      uint32_t *ptr = dir == IPC_COPY_TO ? &r_it->page.cur : &l_it->page.cur;
      uint32_t prev = *ptr;
      int nr_pages = ipc_page_iter_copy (task, &r_it->page, &l_it->page, dir);

      if (nr_pages < 0)
        return (nr_pages);

      data->pages_recv += *ptr - prev;
    }

  return (ret);
}

static struct cap_alert*
cap_flow_alloc_alert (struct cap_flow *flow, uint32_t flg)
{
  if (!slist_empty (&flow->alloc_alerts))
    {
      /*
       * The cached user alerts are inserted at the head, whereas the
       * kernel alerts are appended. Thus, if the first entry is a
       * user one, it can be recycled.
       */
      _Auto entry = slist_first_entry (&flow->alloc_alerts,
                                       struct cap_alert, snode);
      if (cap_alert_type (entry) == CAP_ALERT_USER)
        {
          slist_remove (&flow->alloc_alerts, NULL);
          return (entry);
        }
    }

  spinlock_unlock (&flow->lock);
  void *ptr = kmem_alloc2 (sizeof (struct cap_alert),
                           (flg & CAP_ALERT_NONBLOCK) ? 0 : KMEM_ALLOC_SLEEP);
  spinlock_lock (&flow->lock);

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

  _Auto recv = list_first_entry (&flow->receivers, struct cap_receiver, lnode);
  list_remove (&recv->lnode);
  recv->spurious = true;
  thread_wakeup (recv->thread);
}

int
cap_recv_alert (struct cap_flow *flow, void *buf,
                uint32_t flags, struct ipc_msg_data *mdata)
{
  spinlock_lock (&flow->lock);
  if (plist_empty (&flow->pending_alerts))
    {
      if (flags & CAP_ALERT_NONBLOCK)
        {
          spinlock_unlock (&flow->lock);
          return (EAGAIN);
        }

      struct cap_receiver recv;
      cap_receiver_add (flow, &recv, buf);

      do
        thread_sleep (&flow->lock, flow, "flow-alert");
      while (plist_empty (&flow->pending_alerts));

      if (!recv.spurious)
        {
          spinlock_unlock (&flow->lock);
          if (recv.mdata.nbytes >= 0 && mdata)
            {
              recv.mdata.nbytes = CAP_ALERT_SIZE;
              user_copy_to (mdata, &recv.mdata, sizeof (*mdata));
            }

          return (recv.mdata.nbytes < 0 ? recv.mdata.nbytes : 0);
        }
    }

  _Auto entry = plist_last_entry (&flow->pending_alerts,
                                  struct cap_alert, pnode);

  plist_remove (&flow->pending_alerts, &entry->pnode);
  spinlock_unlock (&flow->lock);
  uint32_t ids[2] = { 0 };

  if (unlikely (user_copy_to (buf, entry->payload, CAP_ALERT_SIZE) != 0))
    {
      SPINLOCK_GUARD (&flow->lock);
      plist_add (&flow->pending_alerts, &entry->pnode);
      cap_recv_wakeup_fast (flow);
      return (EFAULT);
    }
  else if (cap_alert_type (entry) == CAP_ALERT_USER)
    {
      ids[0] = entry->task_id, ids[1] = entry->thread_id;
      SPINLOCK_GUARD (&flow->lock);
      // Put back the alert so it can be reused.
      slist_insert_head (&flow->alloc_alerts, &entry->snode);
    }

  if (mdata)
    {
      struct ipc_msg_data tmp;
      memset (&tmp, 0, sizeof (tmp));

      tmp.nbytes = CAP_ALERT_SIZE;
      if (cap_alert_type (entry) != CAP_ALERT_USER)
        tmp.flags = IPC_MSG_KERNEL;
      else
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

  if (cap->type == CAP_TYPE_CHANNEL)
    {
      flow = ((struct cap_channel *)cap)->flow;
      if (! flow)
        return (EINVAL);
    }
  else if (cap->type == CAP_TYPE_FLOW)
    flow = (struct cap_flow *)cap;
  else
    return (EBADF);

  /*
   * Copy into a temporary buffer, since the code below may otherwise
   * generate a page fault while holding a spinlock.
   */
  char abuf[CAP_ALERT_SIZE] = { 0 };
  if (user_copy_from (abuf, buf, CAP_ALERT_SIZE) != 0)
    return (EFAULT);

  struct cap_receiver *recv;

  {
    SPINLOCK_GUARD (&flow->lock);
    if (list_empty (&flow->receivers))
      {
        _Auto alert = cap_flow_alloc_alert (flow, flags);
        if (! alert)
          return (-ENOMEM);

        memcpy (alert->payload, abuf, CAP_ALERT_SIZE);
        plist_node_init (&alert->pnode, prio);
        plist_add (&flow->pending_alerts, &alert->pnode);
        cap_alert_type(alert) = CAP_ALERT_USER;
        cap_fill_ids (&alert->thread_id, &alert->task_id, thread_self ());
        return (0);
      }

    recv = list_pop (&flow->receivers, typeof (*recv), lnode);
  }

  cap_fill_ids (&recv->mdata.thread_id, &recv->mdata.task_id, thread_self ());
  recv->mdata.nbytes = ipc_bcopy (recv->thread->task, recv->buf, sizeof (abuf),
                                  abuf, sizeof (abuf), IPC_COPY_TO);

  thread_wakeup (recv->thread);
  return (recv->mdata.nbytes < 0 ? recv->mdata.nbytes : 0);
}

static void
cap_sender_add (struct cap_flow *flow, struct cap_sender *sender,
                struct thread *thread)
{
  sender->thread = thread;
  list_insert_tail (&flow->waiters, &sender->lnode);
}

static void
cap_task_swap (struct task **taskp)
{
  barrier ();
  cpu_flags_t flags;
  thread_preempt_disable_intr_save (&flags);

  struct thread *self = thread_self ();
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
  data->nbytes = 0;
  data->flags = 0;
  data->pages_sent = data->caps_sent = 0;
  data->pages_recv = data->caps_recv = 0;
}

static void
cap_iters_copy (struct cap_iters *dst, const struct cap_iters *src)
{
#define copy_simple(d, s, type)   \
  d->type.begin = s->type.begin;   \
  d->type.cur = s->type.cur;   \
  d->type.end = s->type.end

  memcpy (dst->iov.cache, src->iov.cache,
          (src->iov.cache_idx - IPC_IOV_ITER_CACHE_SIZE) *
          sizeof (struct iovec));
  dst->iov.cache_idx = src->iov.cache_idx;
  dst->iov.head = src->iov.head;

  copy_simple (dst, src, iov);
  copy_simple (dst, src, cap);
  copy_simple (dst, src, page);
#undef copy_simple
}

static void
cap_flow_push_port (struct cap_flow *flow, struct cap_port_entry *port)
{
  SPINLOCK_GUARD (&flow->lock);
  slist_insert_head (&flow->lpads, &port->snode);

  if (list_empty (&flow->waiters))
    return;

  _Auto sender = list_first_entry (&flow->waiters, struct cap_sender, lnode);
  thread_wakeup (sender->thread);
}

static ssize_t
cap_sender_impl (struct cap_flow *flow, uintptr_t tag, struct cap_iters *in,
                 struct cap_iters *out, struct ipc_msg_data *data)
{
  struct cap_port_entry *port;
  struct thread *self = thread_self ();

  {
    SPINLOCK_GUARD (&flow->lock);

    if (slist_empty (&flow->lpads))
      {
        struct cap_sender sender;
        cap_sender_add (flow, &sender, self);

        do
          thread_sleep (&flow->lock, flow, "flow-sender");
        while (slist_empty (&flow->lpads));

        list_remove (&sender.lnode);
      }

    port = slist_first_entry (&flow->lpads, typeof (*port), snode);
    slist_remove (&flow->lpads, NULL);
  }
 
  cap_ipc_msg_data_init (&port->mdata, tag);
  ssize_t nb = cap_transfer_iters (port->task, &port->in_it, in,
                                   IPC_COPY_TO, &port->mdata);

  if (nb < 0)
    port->mdata.nbytes = nb;

  cap_iters_copy (&port->in_it, in);
  port->out_it = out;

  struct cap_port_entry *cur_port = self->cur_port;
  self->cur_port = port;
  cap_fill_ids (&port->mdata.thread_id, &port->mdata.task_id, self);

  // Switch task (also sets the pmap).
  cap_task_swap (&port->task);
  user_copy_to ((void *)port->ctx[2], &port->mdata, sizeof (port->mdata));

  // After the copy, switch the counters.
  SWAP (&port->mdata.pages_recv, &port->mdata.pages_sent);
  SWAP (&port->mdata.caps_recv, &port->mdata.caps_sent);
  port->mdata.pages_recv = port->mdata.caps_recv = 0;

  // Jump to new PC and SP.
  ssize_t ret = cpu_port_swap (port->ctx, cur_port, (void *)flow->entry);

  // We're back.
  cap_flow_push_port (flow, port);
  if (data && user_copy_to (data, &port->mdata, sizeof (*data)) != 0)
    ret = -EFAULT;

  self->cur_port = cur_port;
  return (ret);
}

static int
cap_handle_task_thread (struct cap_iters *src, struct cap_iters *dst,
                        struct cap_base *cap)
{
  struct ipc_msg_data mdata;

  return (cap->type == CAP_TYPE_THREAD ?
          thread_handle_msg (((struct cap_thread *)cap)->thread,
                             src, dst, &mdata) :
          task_handle_msg (((struct cap_task *)cap)->task,
                           src, dst, &mdata));
}

ssize_t
cap_send_iters (struct cap_base *cap, struct cap_iters *in,
                struct cap_iters *out, struct ipc_msg_data *data)
{
  struct cap_flow *flow;
  uintptr_t tag;

  if (! cap)
    return (-EBADF);

  switch (cap->type)
    {
      case CAP_TYPE_FLOW:
        flow = (struct cap_flow *)cap;
        tag = flow->tag;
        break;

      case CAP_TYPE_CHANNEL:
        flow = ((struct cap_channel *)cap)->flow;
        if (! flow)
          return (-EINVAL);

        tag = ((struct cap_channel *)cap)->tag;
        break;

      case CAP_TYPE_THREAD:
      case CAP_TYPE_TASK:
        return (cap_handle_task_thread (in, out, cap));

      case CAP_TYPE_KERNEL:
        // TODO: Implement.
      default:
        return (-EINVAL);
    }

  return (cap_sender_impl (flow, tag, in, out, data));
}

static ssize_t
cap_push_pull_msg (struct cap_iters *l_it, struct ipc_msg_data *mdata,
                   int dir, struct cap_iters *r_it, struct cap_port_entry *port)
{
  cap_ipc_msg_data_init (mdata, port->mdata.tag);
  return (cap_transfer_iters (port->task, r_it, l_it, dir, mdata));
}

ssize_t
cap_pull_iters (struct cap_iters *it, struct ipc_msg_data *mdata)
{
  struct thread *self = thread_self ();
  struct cap_port_entry *port = self->cur_port;

  if (! port)
    return (-EINVAL);

  struct ipc_msg_data tmp;
  ssize_t ret = cap_push_pull_msg (it, &tmp, IPC_COPY_FROM,
                                   &port->in_it, port);
  if (ret >= 0)
    {
      port->mdata.pages_sent += tmp.pages_recv;
      port->mdata.caps_sent += tmp.caps_recv;

      if (mdata && user_copy_to (mdata, &tmp, sizeof (tmp)) != 0)
        ret = -EFAULT;
    }

  return (ret);
}

ssize_t
cap_push_iters (struct cap_iters *it, struct ipc_msg_data *mdata)
{
  struct thread *self = thread_self ();
  struct cap_port_entry *port = self->cur_port;

  if (! port)
    return (-EINVAL);

  struct ipc_msg_data out_data;
  ssize_t ret = cap_push_pull_msg (it, &out_data, IPC_COPY_TO,
                                   port->out_it, port);
  if (ret >= 0)
    {
      port->mdata.nbytes += ret;
      port->mdata.pages_recv += out_data.pages_recv;
      port->mdata.caps_recv += out_data.caps_recv;

      if (mdata)
        {
          out_data.pages_sent = out_data.pages_recv;
          out_data.caps_sent = out_data.caps_recv;
          out_data.pages_recv = out_data.caps_recv = 0;
          if (user_copy_to (mdata, &out_data, sizeof (*mdata)) != 0)
            ret = -EFAULT;
        }
    }

  return (ret);
}

ssize_t
cap_reply_iters (struct cap_iters *it, int rv)
{
  struct cap_port_entry *port = thread_self()->cur_port;
  ssize_t ret;

  if (! port)
    return (-EINVAL);
  else if (rv >= 0)
    ret = port->mdata.nbytes =
      cap_transfer_iters (port->task, port->out_it,
                          it, IPC_COPY_TO, &port->mdata);
  else
    ret = rv;

  cap_task_swap (&port->task);
  cpu_port_return (port->ctx[0], ret);
  __builtin_unreachable ();
}

int
cap_flow_add_port (struct cap_flow *flow, void *stack, size_t size,
                   struct ipc_msg *msg, struct ipc_msg_data *mdata,
                   struct cap_thread_info *info __unused)
{
  struct cap_port_entry *entry = kmem_cache_alloc (&cap_port_cache);
  if (! entry)
    return (ENOMEM);

  entry->size = size;
  entry->ctx[0] = (uintptr_t)stack;
  entry->ctx[1] = (uintptr_t)msg;
  entry->ctx[2] = (uintptr_t)mdata;
  memset (&entry->mdata, 0, sizeof (entry->mdata));
  cap_iters_init_msg (&entry->in_it, msg);
  task_ref (entry->task = task_self ());

  cap_flow_push_port (flow, entry);
  return (0);
}

int
cap_flow_rem_port (struct cap_flow *flow, uintptr_t stack)
{
  spinlock_lock (&flow->lock);
  struct cap_port_entry *entry;
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
      spinlock_unlock (&flow->lock);
      return (ESRCH);
    }

  slist_remove (&flow->lpads, prev);
  spinlock_unlock (&flow->lock);

  // Unmap the stack if the user didn't specify one.
  int error = stack != ~(uintptr_t)0 ? 0 :
              vm_map_remove (vm_map_self (), entry->ctx[0], entry->size);

  if (! error)
    kmem_free (entry, sizeof (*entry));
  else
    cap_flow_push_port (flow, entry);

  return (error);
}

static void
cap_notify_intr (struct cap_alert_async *alert)
{
  SPINLOCK_GUARD (&alert->flow->lock);
  if (++alert->base.k_alert.intr.count == 1)
    {
      plist_add (&alert->flow->pending_alerts, &alert->base.pnode);
      cap_recv_wakeup_fast (alert->flow);
    }
}

static int
cap_handle_intr (void *arg)
{
  struct list *list = arg;
  assert (list >= &cap_intr_handlers[0] &&
          list <= &cap_intr_handlers[ARRAY_SIZE (cap_intr_handlers) - 1]);

  RCU_GUARD ();
  list_rcu_for_each (list, tmp)
    cap_notify_intr (list_entry (tmp, struct cap_alert_async, xlink));

  return (EAGAIN);
}

static int
cap_intr_add (uint32_t intr, struct list *node)
{
  ADAPTIVE_LOCK_GUARD (&cap_intr_lock);
  struct list *list = &cap_intr_handlers[intr - CPU_EXC_INTR_FIRST];

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

static int
cap_intr_rem (uint32_t intr, struct list *node)
{
  adaptive_lock_acquire (&cap_intr_lock);
  list_rcu_remove (node);

  if (list_empty (&cap_intr_handlers[intr - CPU_EXC_INTR_FIRST]))
    intr_unregister (intr, cap_handle_intr);

  adaptive_lock_release (&cap_intr_lock);
  rcu_wait ();
  return (0);
}

static struct cap_alert_async*
cap_alert_async_find (struct cap_flow *flow, int type, int id,
                      struct slist_node **prevp)
{
  struct cap_alert *tmp;
  struct slist_node *node = NULL;

  slist_for_each_entry (&flow->alloc_alerts, tmp, snode)
    {
      if (cap_alert_type (tmp) == type && tmp->k_alert.any_id == id)
        {
          if (prevp)
            *prevp = node;

          return ((void *)tmp);
        }

      node = &tmp->snode;
    }

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

  plist_node_init (&ap->base.pnode, ~0u);   // Interrupts have max priority.
  cap_alert_type(&ap->base) = CAP_ALERT_INTR;
  slist_node_init (&ap->base.snode);
  list_node_init (&ap->xlink);
  ap->flow = flow;

  ap->base.k_alert = (struct cap_kern_alert)
    {
      .type = CAP_ALERT_INTR,
      .intr = { .irq = irq, .count = 0 }
    };

  int error = cap_intr_add (irq, &ap->xlink);
  if (error)
    {
      kmem_cache_free (&cap_misc_cache, ap);
      return (error);
    }

  spinlock_lock (&flow->lock);
  if (unlikely (cap_alert_async_find (flow, CAP_ALERT_INTR, irq, NULL)))
    {
      spinlock_unlock (&flow->lock);
      cap_intr_rem (irq, &ap->xlink);
      kmem_cache_free (&cap_misc_cache, ap);
      return (EALREADY);
    }

  slist_insert_tail (&flow->alloc_alerts, &ap->base.snode);
  spinlock_unlock (&flow->lock);
  return (0);
}

int
cap_intr_unregister (struct cap_flow *flow, uint32_t irq)
{
  CPU_INTR_GUARD ();
  spinlock_lock (&flow->lock);

  struct slist_node *node = NULL;
  _Auto entry = cap_alert_async_find (flow, CAP_ALERT_INTR, irq, &node);

  if (! entry)
    {
      spinlock_unlock (&flow->lock);
      return (ESRCH);
    }

  slist_remove (&flow->alloc_alerts, node);
  if (!plist_node_unlinked (&entry->base.pnode))
    plist_remove (&flow->pending_alerts, &entry->base.pnode);

  spinlock_unlock (&flow->lock);
  cap_intr_rem (irq, &entry->xlink);

  return (0);
}

int
(cap_intern) (struct cap_base *cap, int flags)
{
  return (cap ? cspace_add_free (cspace_self (), cap, flags) : -EINVAL);
}

static size_t
cap_max_size (const size_t *args, size_t n)
{
  size_t ret = *args;
  for (size_t i = 1; i < n; ++i)
    if (args[i] > ret)
      ret = args[i];

  return (ret);
}

#define CAP_MAX_SIZE(...)   \
  ({   \
     const size_t args_[] = { __VA_ARGS__ };   \
     cap_max_size (args_, ARRAY_SIZE (args_));   \
   })

static int __init
cap_setup (void)
{
  // Every capability type but flows are allocated from the same cache.
#define SZ(type)   sizeof (struct cap_##type)
  size_t size = CAP_MAX_SIZE (SZ (task), SZ (thread), SZ (channel),
                              SZ (kernel), SZ (alert_async));

  kmem_cache_init (&cap_misc_cache, "cap_misc", size, 0, NULL, 0);
  kmem_cache_init (&cap_flow_cache, "cap_flow",
                   sizeof (struct cap_flow), 0, NULL, 0);
  kmem_cache_init (&cap_port_cache, "cap_port",
                   sizeof (struct cap_port_entry), 0, NULL, 0);

  adaptive_lock_init (&cap_intr_lock);
  for (size_t i = 0; i < ARRAY_SIZE (cap_intr_handlers); ++i)
    list_init (&cap_intr_handlers[i]);

  return (0);
}

INIT_OP_DEFINE (cap_setup,
                INIT_OP_DEP (intr_setup, true),
                INIT_OP_DEP (kmem_setup, true));
