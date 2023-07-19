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
 */

#include <kern/capability.h>
#include <kern/cspace.h>
#include <kern/intr.h>
#include <kern/kmem.h>
#include <kern/rcu.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/user.h>

struct cap_alert_base
{
  struct plist_node pnode;
  char payload[CAP_ALERT_SIZE + 1];
};

union cap_alert_user
{
  // State when active.
  struct cap_alert_base base;
  // State when in the freelist.
  struct slist_node snode;
};

struct cap_alert_async
{
  struct cap_alert_base base;
  struct slist_node lnode;
  struct list xlink;
  struct cap_flow *flow;
};

struct cap_sender
{
  struct plist_node node;
  ssize_t result;
  void **flowp;
  void *flow_store;
  struct thread *thread;
  struct thread *handler;
  struct thread_sched_data sender_sched;
  struct thread_sched_data recv_sched;
  struct cap_iters *in_it;
  struct cap_iters *out_it;
  struct ipc_msg_data ipc_data;
};

struct cap_receiver
{
  struct cap_iters *it;
  struct thread *thread;
  struct list node;
  struct ipc_msg_data ipc_data;
  rcvid_t rcvid;
  bool spurious;
};

static struct kmem_cache cap_flow_cache;
static struct kmem_cache cap_misc_cache;

static struct list cap_intr_handlers[CPU_INTR_TABLE_SIZE];
static struct adaptive_lock cap_intr_lock;

/*
 * The byte following the plist node indicates whether the object is
 * an alert or a regular message with a thread blocking on it.
 */

static void
cap_pnode_mark (struct plist_node *node, int type)
{
  *(char *)(node + 1) = type;
}

static void
cap_pnode_mark_ualert (struct plist_node *node)
{
  cap_pnode_mark (node, 1);
}

static void
cap_pnode_mark_msg (struct plist_node *node)
{
  cap_pnode_mark (node, 0);
}

static int
cap_pnode_type (struct plist_node *node)
{
  return (*(char *)(node + 1));
}

// This is a macro to work around typing issues.
#define cap_alert_buf(alert)   (&((struct cap_alert_base *)alert)->payload[1])

#define CAP_FLOW_EXITING   0x01

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

static void cap_alert_async_rem (struct cap_alert_async *);

static void
cap_flow_fini (struct sref_counter *sref)
{
  _Auto flow = CAP_FROM_SREF (sref, struct cap_flow);

  {
    SPINLOCK_INTR_GUARD (&flow->lock);
    flow->flags |= CAP_FLOW_EXITING;
  }

  struct cap_alert_async *aentry, *atmp;
  slist_for_each_entry_safe (&flow->alert_kern, aentry, atmp, lnode)
    {
      cap_alert_async_rem (aentry);
      kmem_cache_free (&cap_misc_cache, aentry);
    }

  union cap_alert_user *uentry, *utmp;
  slist_for_each_entry_safe (&flow->alert_user, uentry, utmp, snode)
    kmem_free (uentry, sizeof (*uentry));

  // Wake pending senders.
  plist_for_each (&flow->senders, pnode)
    {
      int type = cap_pnode_type (pnode);
      if (type == 1)
        // Regular alert.
        kmem_free (pnode, sizeof (union cap_alert_user));
      else if (type == 0)
        { // Sender thread.
          _Auto sender = plist_entry (pnode, struct cap_sender, node);
          sender->result = -EBADF;
          thread_wakeup (sender->thread);
        }
    }

  // Wake pending receivers.
  list_for_each (&flow->receivers, node)
    {
      _Auto recv = structof (node, struct cap_receiver, node);
      recv->rcvid = -EBADF;
      thread_wakeup (recv->thread);
    }

  kmem_cache_free (&cap_flow_cache, flow);
}

int
cap_flow_create (struct cap_flow **outp, uint32_t flags, uintptr_t tag)
{
  struct cap_flow *ret = kmem_cache_alloc (&cap_flow_cache);
  if (! ret)
    return (ENOMEM);

  cap_base_init (&ret->base, CAP_TYPE_FLOW, cap_flow_fini);
  spinlock_init (&ret->lock);
  plist_init (&ret->senders);
  list_init (&ret->receivers);
  slist_init (&ret->alert_user);
  slist_init (&ret->alert_kern);
  ret->flags = flags;
  ret->tag = tag;

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
cap_sender_init (struct cap_sender *sender, struct cap_flow *flow,
                 struct cap_iters *src, struct cap_iters *dst, uintptr_t tag)
{
  cap_ipc_msg_data_init (&sender->ipc_data, tag);
  sender->thread = thread_self ();
  sender->flow_store = flow;
  sender->flowp = &sender->flow_store;
  sender->handler = NULL;
  sender->result = 0;
  sender->in_it = src;
  sender->out_it = dst;
}

static void
cap_receiver_init (struct cap_receiver *recv, struct thread *self,
                   int cap, struct cap_iters *it)
{
  cap_ipc_msg_data_init (&recv->ipc_data, 0);
  recv->thread = self;
  recv->rcvid = (uint64_t)cap << 32;
  recv->it = it;
  recv->spurious = false;
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
      int nr_msg = ipc_cap_iter_copy (task, &r_it->cap, &l_it->cap, dir);
      if (nr_msg < 0)
        return (nr_msg);

      data->caps_recv += nr_msg;
    }

  if (ipc_page_iter_size (&r_it->page) && ipc_page_iter_size (&l_it->page))
    {
      uint32_t *ptr = dir == IPC_COPY_TO ? &r_it->page.cur : &l_it->page.cur;
      uint32_t prev = *ptr;
      int nr_msg = ipc_page_iter_copy (task, &r_it->page, &l_it->page, dir);

      if (nr_msg < 0)
        return (nr_msg);

      data->pages_recv += *ptr - prev;
    }

  return (ret);
}

static struct cap_sender*
cap_thread_sender (struct thread *thr)
{
  return ((void *)thread_wchan_addr (thr));
}

static void
cap_sender_receiver_step (struct cap_sender *sender, struct cap_receiver *recv,
                          struct cap_flow *flow)
{
  // Update counters and handler thread.
  sender->ipc_data.caps_sent += recv->ipc_data.caps_recv;
  sender->ipc_data.pages_sent += recv->ipc_data.pages_recv;
  sender->handler = recv->thread;

  // Complete the receive ID and set the tag.
  struct thread *thread = sender->thread;
  recv->rcvid |= thread_id (thread);
  recv->thread->cur_peer = thread;
  recv->thread->cur_rcvid = recv->rcvid;
  recv->ipc_data.tag = sender->ipc_data.tag;

  if (thread->cur_peer)
    { // The sender is acting on a peer's message - Update metadata.
      _Auto prev_sender = cap_thread_sender (thread->cur_peer);
      sender->flow_store = *prev_sender->flowp;
      *prev_sender->flowp = flow;
      sender->flowp = prev_sender->flowp;
    }

  // Fill in the rest of the metadata.
  recv->ipc_data.thread_id = thread_id (thread);
  recv->ipc_data.task_id = task_id (thread->task);
}

static ssize_t
cap_recv_putback (struct cap_flow *flow, struct cap_receiver *recv, ssize_t rv)
{
  if (-rv == EFAULT || -rv == EACCES)
    { // The problem was in the sender's buffers. Put back the receiver.
      SPINLOCK_GUARD (&flow->lock);
      list_insert_tail (&flow->receivers, &recv->node);
      return (rv);
    }

  recv->rcvid = rv;
  thread_wakeup (recv->thread);
  return (rv);
}

static void
cap_sender_enqueue (struct cap_sender *sender, struct cap_flow *flow)
{
  plist_node_init (&sender->node,
                   thread_real_global_priority (sender->thread));
  plist_add (&flow->senders, &sender->node);
  cap_pnode_mark_msg (&sender->node);
  // TODO: Priority inheritance.
  sender->sender_sched = *thread_get_real_sched_data(sender->thread);
}

static ssize_t
cap_sender_impl (struct cap_sender *sender, struct cap_flow *flow)
{
  struct cap_receiver *recv;

  {
    SPINLOCK_GUARD (&flow->lock);
    if (flow->flags & CAP_FLOW_EXITING)
      return (-EBADF);
    else if (list_empty (&flow->receivers))
      { // Add ourselves to the list of senders.
        cap_sender_enqueue (sender, flow);
        int error = thread_send_block (&flow->lock, sender);
        if (error)
          {
            plist_remove (&flow->senders, &sender->node);
            return (error);
          }
        
        // The receiver does all the work in this case.
        return (sender->result);
      }

    recv = list_pop (&flow->receivers, typeof (*recv), node);
  }

  ssize_t tmp = cap_transfer_iters (recv->thread->task, recv->it,
                                    sender->in_it, IPC_COPY_TO,
                                    &recv->ipc_data);
  if (tmp < 0)
    return (cap_recv_putback (flow, recv, tmp));

  cap_sender_receiver_step (sender, recv, flow);

  // Switch to handler thread and return result.
  sender->recv_sched = *thread_get_real_sched_data(recv->thread);
  thread_handoff (sender->thread, recv->thread, sender, &sender->sender_sched);
  return (sender->result);
}

static int
cap_flow_alloc_alert (struct cap_flow *flow, int flags,
                      union cap_alert_user **outp)
{
  if (!slist_empty (&flow->alert_user))
    {
      *outp = slist_first_entry (&flow->alert_user,
                                 union cap_alert_user, snode);
      slist_remove (&flow->alert_user, NULL);
      return (0);
    }

  spinlock_unlock (&flow->lock);
  void *ptr = kmem_alloc2 (sizeof (union cap_alert_user),
                           (flags & CAP_ALERT_BLOCK) ? KMEM_ALLOC_SLEEP : 0);
  spinlock_lock (&flow->lock);

  if (! ptr)
    return (ENOMEM);

  *outp = ptr;
  return (0);
}

static ssize_t
cap_send_small (struct cap_receiver *recv, const void *buf,
                size_t size, uint32_t flags)
{
  struct ipc_iov_iter tmp;
  ipc_iov_iter_init_buf (&tmp, (void *)buf, size);
  ssize_t rv = ipc_iov_iter_copy (recv->thread->task, &recv->it->iov,
                                  &tmp, IPC_COPY_TO);

  if (unlikely (rv < 0))
    return (-rv);

  recv->ipc_data.nbytes = rv;
  recv->ipc_data.flags |= flags;
  recv->rcvid = 0;
  thread_wakeup (recv->thread);
  return (0);
}

ssize_t
(cap_send_alert) (struct cap_base *cap, const void *buf,
                  size_t size, uint32_t flags, uint32_t priority)
{
  if (size > CAP_ALERT_SIZE)
    return (E2BIG);

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

  char abuf[CAP_ALERT_SIZE];

  /*
   * Copy into a temporary buffer, since the code below may otherwise
   * generate a page fault while holding a spinlock.
   */
  memset (abuf, 0, sizeof (abuf));
  if (user_copy_from (abuf, buf, MIN (CAP_ALERT_SIZE, size)) != 0)
    return (EFAULT);

  struct cap_receiver *recv;

  {
    SPINLOCK_GUARD (&flow->lock);

    if (flow->flags & CAP_FLOW_EXITING)
      return (-EBADF);
    else if (list_empty (&flow->receivers))
      {
        union cap_alert_user *alert;
        int error = cap_flow_alloc_alert (flow, flags, &alert);

        if (error)
          return (error);

        memcpy (cap_alert_buf (alert), abuf, size);
        plist_node_init (&alert->base.pnode, priority);
        plist_add (&flow->senders, &alert->base.pnode);
        cap_pnode_mark_ualert (&alert->base.pnode);

        return (0);
      }

    recv = list_pop (&flow->receivers, typeof (*recv), node);
  }

  return (cap_send_small (recv, abuf, sizeof (abuf), 0));
}

/*
 * A receive ID is a 64-bit integer, composed of a capability index
 * and a thread ID. When decoding it, the following invariants must apply:
 *
 * - Both the capability index and thread ID must reflect valid entities.
 * - The thread must be either sending a message or awaiting a reply.
 * - The capability described by the index must be equal to the one the
 *   thread sent a message to.
 * - The current thread must be equal to the one the thread is paired to.
 *   Alternatively, the thread could be waiting on no other thread (as when
 *   calling 'cap_rcvid_detach'), in which case the current thread can become
 *   the new handler thread if needed.
 *
 * The thread's runq lock must be held when accessing the wait channel address,
 * since that member is otherwise only set by the owner thread.
 */

static int
cap_thread_validate (struct thread *thr, void *flow, struct thread *self)
{
  if (!thread_send_reply_blocked (thr))
    return (-EINVAL);

  _Auto sender = cap_thread_sender (thr);
  if (!sender || *sender->flowp != flow)
    return (-EINVAL);
  else if (!sender->handler)
    sender->handler = self;
  else if (sender->handler != self)
    return (-EAGAIN);

  return (0);
}

/*
 * Decode a receive ID, returning both the capability and thread, as
 * described in the above comment.
 */

static int
cap_rcvid_decode (rcvid_t rcvid, struct thread *self,
                  struct cap_base **capp, struct thread **thrp)
{
  int capx = (int)(rcvid >> 32);
  int tid = (int)(rcvid & 0xffffffff);

  if (capx < 0 || tid <= 0)
    return (-EBADF);

  _Auto cap = cspace_get (&self->task->caps, capx);
  if (! cap)
    return (-ESRCH);

  _Auto thread = thread_by_kuid (tid);
  if (! thread)
    {
      cap_base_rel (cap);
      return (-ESRCH);
    }

  cpu_flags_t flags;
  _Auto runq = thread_lock_runq (thread, &flags);

  int error = cap_thread_validate (thread, cap, self);
  thread_unlock_runq (runq, flags);

  if (error)
    {
      cap_base_rel (cap);
      thread_unref (thread);
      return (error);
    }

  *capp = cap;
  *thrp = thread;
  return (0);
}

static void
cap_thread_swap_sched (struct thread *thr, struct thread_sched_data *prev,
                       struct thread_sched_data *next)
{
  *prev = *thread_get_real_sched_data(thr);
  thread_setscheduler (thr, next->sched_policy, next->global_priority);
}

static void
cap_rcvid_detach (struct thread *self)
{
  if (!self->cur_peer)
    return;

  _Auto sender = cap_thread_sender (self->cur_peer);
  cap_thread_swap_sched (self, &sender->sender_sched, &sender->recv_sched);
  sender->handler = NULL;
  self->cur_peer = NULL;
  self->cur_rcvid = 0;
}

static struct cap_sender*
cap_sender_stop (struct cap_sender *sender)
{
  sender->handler = (struct thread *)1;
  return (sender);
}

static struct cap_sender*
cap_rcvid_acq_rel_sender (struct thread *self, rcvid_t rcvid, int *errp)
{
  if (self->cur_rcvid == rcvid)
    {
      _Auto sender = cap_thread_sender (self->cur_peer);
      self->cur_rcvid = 0;
      self->cur_peer = NULL;
      cap_thread_swap_sched (self, &sender->sender_sched, &sender->recv_sched);
      return (cap_sender_stop (sender));
    }

  struct cap_base *cap;
  struct thread *thread;
  int error = cap_rcvid_decode (rcvid, self, &cap, &thread);

  if (error)
    {
      *errp = -error;
      return (NULL);
    }

  cap_rcvid_detach (self);
  _Auto sender = cap_sender_stop (cap_thread_sender (thread));
  thread_unref (thread);
  cap_base_rel (cap);
  return (sender);
}

static void
cap_recv_wakeup_fast (struct cap_flow *flow)
{
  if (list_empty (&flow->receivers))
    return;

  _Auto recv = list_pop (&flow->receivers, struct cap_receiver, node);
  recv->spurious = true;
  thread_wakeup (recv->thread);
}

static int
cap_recv_alert (struct cap_receiver *recv, struct cap_alert_base *alert,
                struct spinlock *lock)
{
  const char *buf = cap_alert_buf (alert);

  if (cap_pnode_type (&alert->pnode) == CAP_KERN_ALERT_INTR)
    { // Use a temporary buffer to prevent racing against another interrupt.
      char *tmp = alloca (CAP_ALERT_SIZE);
      memcpy (tmp, buf, CAP_ALERT_SIZE);
      buf = tmp;
    }

  spinlock_unlock (lock);
  _Auto base = recv->it->iov.begin;
  _Auto end = base + recv->it->iov.end;
  size_t size = CAP_ALERT_SIZE;

  for (; base < end && size; ++base)
    {
      size_t len = MIN (size, base->iov_len);
      if (user_copy_to (base->iov_base, buf, len) != 0)
        return (EFAULT);

      buf = (const char *)buf + len;
      size -= len;
    }

  return (0);
}

static rcvid_t
cap_receiver_impl (struct cap_receiver *recv, struct cap_flow *flow)
{
  struct plist_node *pnode = NULL;
  cap_rcvid_detach (recv->thread);

retry:
  spinlock_lock (&flow->lock);

  if (flow->flags & CAP_FLOW_EXITING)
    return (-EBADF);
  else if (plist_empty (&flow->senders))
    {
      list_insert_tail (&flow->receivers, &recv->node);
      int error = thread_recv_block (&flow->lock, recv);
      if (error)
        {
          list_remove (&recv->node);
          spinlock_unlock (&flow->lock);
          return (-error);
        }

      spinlock_unlock (&flow->lock);
      if (recv->spurious)
        {
          recv->spurious = false;
          goto retry;
        }

      // The sender completed the id and woke us up.
      return (recv->rcvid);
    }
  else
    {
      pnode = plist_last (&flow->senders);
      plist_remove (&flow->senders, pnode);
    }

  int ps = cap_pnode_type (pnode);

  if (ps)
    { // Message was an alert.
      _Auto alert = plist_entry (pnode, struct cap_alert_base, pnode);
      plist_node_unlink (&alert->pnode);
      int error = cap_recv_alert (recv, alert, &flow->lock);

      SPINLOCK_GUARD (&flow->lock);
      if (unlikely (error))
        { // Put back the alert.
          plist_add (&flow->senders, &alert->pnode);
          cap_recv_wakeup_fast (flow);
        }
      else if (ps >= CAP_KERN_ALERT_INTR)
        // Alert was sent by the kernel.
        recv->ipc_data.flags |= IPC_MSG_KERNEL;
      else
        // Regular alert. Put it in the cache for later reuse.
        slist_insert_head (&flow->alert_user,
                           &((union cap_alert_user *)alert)->snode);

      return (error);
    }

  spinlock_unlock (&flow->lock);
  _Auto sender = plist_entry (pnode, struct cap_sender, node);
  ssize_t tmp = cap_transfer_iters (sender->thread->task, sender->in_it,
                                    recv->it, IPC_COPY_FROM, &recv->ipc_data);

  if (tmp < 0)
    {
      sender->result = tmp;
      thread_wakeup (sender->thread);
      if (-tmp == EPERM || -tmp == ENXIO)
        // The error was in the sender's buffers. Back to sleep.
        goto retry;

      return (tmp);
    }

  cap_sender_receiver_step (sender, recv, flow);

  // Inherit the scheduling context and return.
  sender->recv_sched = *thread_get_real_sched_data(recv->thread);
  thread_adopt (sender->thread, recv->thread);
  return (recv->rcvid);
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

static void
cap_sender_exit (struct cap_sender *sender)
{
  struct thread *self = sender->thread;
  if (self->cur_peer)
    {
      _Auto prev_sender = cap_thread_sender (self->cur_peer);
      *prev_sender->flowp = sender->flow_store;
    }
}

ssize_t
(cap_send_iters) (struct cap_base *cap, struct cap_iters *src,
                  struct cap_iters *dst, struct ipc_msg_data *data)
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
        return (cap_handle_task_thread (src, dst, cap));
      case CAP_TYPE_KERNEL:
        // TODO: Implement.
      default:
        return (-EINVAL);
    }

  struct cap_sender sender;
  cap_sender_init (&sender, flow, src, dst, tag);

  ssize_t ret = cap_sender_impl (&sender, flow);
  if (ret >= 0 && data)
    user_copy_to (data, &sender.ipc_data, sizeof (*data));

  cap_sender_exit (&sender);
  return (ret);
}

static void
cap_base_rel_guard (struct cap_base **bp)
{
  cap_base_rel (*bp);
}

rcvid_t
cap_recv_iter (int capx, struct cap_iters *it, struct ipc_msg_data *data)
{
  _Auto self = thread_self ();
  _Auto cap = cspace_get (&self->task->caps, capx);

  if (! cap)
    return (-EBADF);

  struct cap_flow *flow;
  struct cap_base *tmp CLEANUP (cap_base_rel_guard) __unused = cap;

  if (cap->type == CAP_TYPE_FLOW)
    flow = (struct cap_flow *)cap;
  else if (cap->type == CAP_TYPE_CHANNEL)
    {
      flow = ((struct cap_channel *)cap)->flow;
      if (! flow)
        return (-EINVAL);
    }
  else
    return (-EINVAL);

  struct cap_receiver rcv;
  cap_receiver_init (&rcv, self, capx, it);

  rcvid_t ret = cap_receiver_impl (&rcv, flow);
  if (ret >= 0 && data)
    user_copy_to (data, &rcv.ipc_data, sizeof (*data));

  return (ret);
}

int
cap_reply_iter (rcvid_t rcvid, struct cap_iters *it, int rv)
{
  int error;
  struct thread *self = thread_self ();
  _Auto sender = cap_rcvid_acq_rel_sender (self, rcvid, &error);

  if (! sender)
    return (error);
  else if (rv >= 0)
    {
      ssize_t bytes = cap_transfer_iters (sender->thread->task,
                                          sender->out_it, it,
                                          IPC_COPY_TO, &sender->ipc_data);
      if (bytes >= 0)
        {
          sender->result = sender->ipc_data.nbytes;
          sender->ipc_data.task_id = task_id (self->task);
          sender->ipc_data.thread_id = thread_id (self);
        }
      else
        sender->result = bytes;
    }
  else
    sender->result = rv;

  thread_setscheduler (sender->thread, sender->sender_sched.sched_policy,
                       sender->sender_sched.global_priority);
  thread_wakeup (sender->thread);
  return (rv < 0 ? (int)-rv : 0);
}

int
(cap_intern) (struct cap_base *cap, int flags)
{
  return (cap ? cspace_add_free (cspace_self (), cap, flags) : -EINVAL);
}

static int
cap_rcvid_acq_sender (struct thread *self, rcvid_t rcvid)
{
  struct cap_base *cap;
  struct thread *thread;
  int error = cap_rcvid_decode (rcvid, self, &cap, &thread);
  if (error)
    return (error);

  cap_rcvid_detach (self);
  self->cur_rcvid = rcvid;
  self->cur_peer = thread;

  _Auto sender = cap_thread_sender (thread);
  cap_thread_swap_sched (self, &sender->recv_sched, &sender->sender_sched);
  cap_base_rel (cap);
  thread_unref (thread);
  return (0);
}

int
cap_handle (rcvid_t rcvid)
{
  struct thread *self = thread_self ();
  if (self->cur_rcvid == rcvid)
    return (0);
  else if (rcvid)
    return (cap_rcvid_acq_sender (self, rcvid));
  else if (!self->cur_peer)
    return (EINVAL);

  _Auto sender = cap_thread_sender (self->cur_peer);
  self->cur_rcvid = 0;
  self->cur_peer = NULL;
  cap_thread_swap_sched (self, &sender->sender_sched, &sender->recv_sched);
  return (0);
}

static ssize_t
cap_push_pull_msg (struct cap_sender *sender, struct cap_iters *l_it,
                   struct ipc_msg_data *mdata, int dir,
                   struct cap_iters *r_it)
{
  cap_ipc_msg_data_init (mdata, sender->ipc_data.tag);
  _Auto task = sender->thread->task;

  ssize_t bytes = cap_transfer_iters (task, r_it, l_it, dir, mdata);
  if (bytes >= 0)
    {
      mdata->thread_id = thread_id (sender->thread);
      mdata->task_id = task_id (task);
    }

  return (bytes);
}

ssize_t
cap_pull_iter (rcvid_t rcvid, struct cap_iters *it, struct ipc_msg_data *mdata)
{
  if (rcvid <= 0)
    return (-EBADF);

  struct thread *self = thread_self ();
  if (self->cur_rcvid != rcvid)
    {
      int error = cap_rcvid_acq_sender (self, rcvid);
      if (error)
        return (-error);
    }

  _Auto sender = cap_thread_sender (self->cur_peer);
  ssize_t ret = cap_push_pull_msg (sender, it, mdata,
                                   IPC_COPY_FROM, sender->in_it);

  if (ret >= 0)
    {
      sender->ipc_data.pages_sent += mdata->pages_recv;
      sender->ipc_data.caps_sent += mdata->caps_recv;
    }

  return (ret);
}

ssize_t
cap_push_iter (rcvid_t rcvid, struct cap_iters *it,
               struct ipc_msg_data *mdata)
{
  if (rcvid <= 0)
    return (-EBADF);

  struct thread *self = thread_self ();
  if (self->cur_rcvid != rcvid)
    {
      int error = cap_rcvid_acq_sender (self, rcvid);
      if (error)
        return (-error);
    }

  _Auto sender = cap_thread_sender (self->cur_peer);
  struct ipc_msg_data out_data;
  ssize_t ret = cap_push_pull_msg (sender, it, &out_data,
                                   IPC_COPY_TO, sender->out_it);

  if (ret >= 0)
    {
      sender->ipc_data.nbytes += ret;
      sender->ipc_data.pages_recv += out_data.pages_recv;
      sender->ipc_data.caps_recv += out_data.caps_recv;
      mdata->pages_sent = out_data.pages_recv;
      mdata->caps_sent = out_data.caps_recv;
    }

  return (ret);
}

#define cap_reset_iter_single(it)   (it)->cur = 0
#define cap_reset_iter(it)   \
  (cap_reset_iter_single (&(it)->iov),   \
   cap_reset_iter_single (&(it)->cap),   \
   cap_reset_iter_single (&(it)->page))

int
cap_redirect (rcvid_t rcvid, struct cap_base *cap)
{
  struct thread *self = thread_self ();
  int error;
  _Auto sender = cap_rcvid_acq_rel_sender (self, rcvid, &error);

  if (! sender)
    return (error);

  struct cap_flow *flow = NULL;

  cap_reset_iter (sender->in_it);
  cap_reset_iter (sender->out_it);

  switch (cap->type)
    {
      case CAP_TYPE_FLOW:
        flow = (struct cap_flow *)cap;
        break;
      case CAP_TYPE_CHANNEL:
        flow = ((struct cap_channel *)cap)->flow;
        break;
      case CAP_TYPE_TASK:
      case CAP_TYPE_THREAD:
        return (cap_handle_task_thread (sender->in_it, sender->out_it, cap));
      case CAP_TYPE_KERNEL:
        // XXX: Implement.
        return (EINVAL);
    }

  spinlock_lock (&flow->lock);
  cap_sender_enqueue (sender, flow);
  cap_recv_wakeup_fast (flow);
  spinlock_unlock (&flow->lock);
  return (0);
}

#undef cap_reset_iter
#undef cap_reset_iter_single

static inline void
cap_copy4 (void *dst, const void *src)
{
  char *dp = dst;
  const char *sp = src;

  for (size_t i = 0; i < sizeof (uint32_t); ++i)
    *dp++ = *sp++;
}

static int
cap_notify_intr (struct list *node)
{
  _Auto ep = list_entry (node, struct cap_alert_async, xlink);
  _Auto flow = ep->flow;
  char *buf = cap_alert_buf (ep) +
              offsetof (struct cap_kern_alert, intr.count);

  {
    SPINLOCK_GUARD (&flow->lock);
    if (flow->flags & CAP_FLOW_EXITING)
      return (EAGAIN);

    uint32_t cnt;
    cap_copy4 (&cnt, buf);

    ++cnt;
    cap_copy4 (buf, &cnt);

    if (cnt > 1)
      return (EINPROGRESS);

    plist_add (&flow->senders, &ep->base.pnode);
    cap_recv_wakeup_fast (flow);
    return (EINPROGRESS);
  }
}

static int
cap_handle_intr (void *arg)
{
  struct list *list = arg;
  assert (list >= &cap_intr_handlers[0] &&
          list <= &cap_intr_handlers[ARRAY_SIZE (cap_intr_handlers) - 1]);

  int ret = EAGAIN;
  RCU_GUARD ();

  list_rcu_for_each (list, tmp)
    {
      int rv = cap_notify_intr (tmp);
      if (rv == EINPROGRESS)
        ret = rv;
    }

  return (ret);
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

static int
cap_alert_async_id (struct cap_alert_async *entry)
{
  uint32_t val;
  memcpy (&val, cap_alert_buf (entry) +
          offsetof (struct cap_kern_alert, any_id),
          sizeof (val));
  return ((int)val);
}

static void
cap_alert_async_rem (struct cap_alert_async *alert)
{
  switch (cap_pnode_type (&alert->base.pnode))
    {
      case CAP_KERN_ALERT_INTR:
        cap_intr_rem (cap_alert_async_id (alert), &alert->xlink);
        break;

      default:
        // XXX: Implement.
        break;
    }
}

static struct cap_alert_async*
cap_alert_async_find (struct cap_flow *flow, int type, int id,
                      struct slist_node **prevp)
{
  struct cap_alert_async *tmp;
  struct slist_node *node = NULL;

  slist_for_each_entry (&flow->alert_kern, tmp, lnode)
    {
      if (cap_pnode_type (&tmp->base.pnode) == type &&
          cap_alert_async_id (tmp) == id)
        {
          if (prevp)
            *prevp = node;

          return (tmp);
        }

      node = &tmp->lnode;
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
  cap_pnode_mark (&ap->base.pnode, CAP_KERN_ALERT_INTR);
  slist_node_init (&ap->lnode);
  list_node_init (&ap->xlink);
  ap->flow = flow;

  struct cap_kern_alert store =
    {
      .type = CAP_KERN_ALERT_INTR,
      .intr = { .irq = irq, .count = 0 }
    };

  memcpy (cap_alert_buf (ap), &store, sizeof (store));

  int error = cap_intr_add (irq, &ap->xlink);
  if (error)
    {
      kmem_cache_free (&cap_misc_cache, ap);
      return (error);
    }

  spinlock_lock (&flow->lock);
  if (unlikely (cap_alert_async_find (flow, CAP_KERN_ALERT_INTR, irq, NULL)))
    {
      spinlock_unlock (&flow->lock);
      cap_intr_rem (irq, &ap->xlink);
      kmem_cache_free (&cap_misc_cache, ap);
      return (EALREADY);
    }

  slist_insert_tail (&flow->alert_kern, &ap->lnode);
  spinlock_unlock (&flow->lock);
  return (0);
}

int
cap_intr_unregister (struct cap_flow *flow, uint32_t irq)
{
  CPU_INTR_GUARD ();
  spinlock_lock (&flow->lock);

  struct slist_node *node = NULL;
  _Auto entry = cap_alert_async_find (flow, CAP_KERN_ALERT_INTR, irq, &node);

  if (! entry)
    {
      spinlock_unlock (&flow->lock);
      return (EINVAL);
    }

  slist_remove (&flow->alert_kern, node);
  if (!plist_node_unlinked (&entry->base.pnode))
    plist_remove (&flow->senders, &entry->base.pnode);

  spinlock_unlock (&flow->lock);
  cap_intr_rem (irq, &entry->xlink);

  return (0);
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

  adaptive_lock_init (&cap_intr_lock);
  for (size_t i = 0; i < ARRAY_SIZE (cap_intr_handlers); ++i)
    list_init (&cap_intr_handlers[i]);

  return (0);
}

INIT_OP_DEFINE (cap_setup,
                INIT_OP_DEP (intr_setup, true),
                INIT_OP_DEP (kmem_setup, true));
