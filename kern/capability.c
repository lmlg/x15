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

union cap_alert
{
  struct
    { // State used when the alert is enqueued.
      struct plist_node pnode;
      char payload[CAP_ALERT_SIZE + 1];
    };

  // State when in the freelist.
  struct slist_node snode;
};

#define CAP_ALERTS_PER_NODE   \
  ((PAGE_SIZE / 2 - sizeof (void *)) / sizeof (union cap_alert) - 1)

struct cap_alert_node
{
  struct cap_alert_node *next;
  union cap_alert alerts[CAP_ALERTS_PER_NODE];
};

struct cap_iters
{
  struct ipc_iov_iter iov;
  struct ipc_cap_iter cap;
  struct ipc_page_iter page;
};

struct cap_sender
{
  struct plist_node node;
  ssize_t result;
  void *flow;
  struct thread *thread;
  struct thread *handler;
  struct thread_sched_data sender_sched;
  struct thread_sched_data recv_sched;
  struct cap_iters in_it;
  struct cap_iters out_it;
  struct ipc_msg_data ipc_data;
};

struct cap_receiver
{
  struct cap_iters it;
  struct thread *thread;
  struct list node;
  struct ipc_msg_data ipc_data;
  rcvid_t rcvid;
  bool spurious;
};

struct cap_intr_entry
{
  struct list cap_node;
  struct list intr_node;
  uint32_t irq;
  struct cap_flow *flow;
};

static struct kmem_cache cap_flow_cache;
static struct kmem_cache cap_misc_cache;
static struct kmem_cache cap_alert_cache;

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

static int cap_intr_rem (uint32_t intr, struct list *node, bool eoi);

static void
cap_flow_fini (struct sref_counter *sref)
{
  _Auto flow = CAP_FROM_SREF (sref, struct cap_flow);
  BITMAP_DECLARE (pending, CPU_INTR_TABLE_SIZE);

  {
    SPINLOCK_GUARD (&flow->lock);
    bitmap_copy (pending, flow->intr.pending, CPU_INTR_TABLE_SIZE);
    // This makes interrupt notification always be marked as spurious.
    bitmap_fill (flow->intr.pending, CPU_INTR_TABLE_SIZE);
  }

  if (unlikely (!list_empty (&flow->intr.entries)))
    {
      struct cap_intr_entry *entry, *tmp;
      list_for_each_entry_safe (&flow->intr.entries, entry, tmp, cap_node)
        cap_intr_rem (entry->irq, &entry->intr_node,
                      bitmap_test (pending, entry->irq));
    }

  for (_Auto al = flow->alnodes; al != NULL; )
    {
      _Auto tmp = al->next;
      kmem_cache_free (&cap_alert_cache, al);
      al = tmp;
    }

  kmem_cache_free (&cap_flow_cache, flow);
}

static struct cap_alert_node*
cap_alert_alloc (struct slist *outp)
{
  slist_init (outp);
  struct cap_alert_node *np = kmem_cache_salloc (&cap_alert_cache);
  if (! np)
    return (NULL);

  for (size_t i = 0; i < ARRAY_SIZE (np->alerts); ++i)
    slist_insert_tail (outp, &np->alerts[i].snode);

  return (np);
}

static void
cap_flow_push_alnode (struct cap_flow *flow, struct slist *slist,
                      struct cap_alert_node *node)
{
  slist_concat (&flow->alert_list, slist);
  node->next = flow->alnodes;
  flow->alnodes = node;
}

static int
cap_flow_alloc_alerts (struct cap_flow *flow)
{
  struct slist tmp;
  _Auto node = cap_alert_alloc (&tmp);

  if (! node)
    return (-ENOMEM);

  cap_flow_push_alnode (flow, &tmp, node);
  return (0);
}

static void
cap_flow_intr_init (struct cap_intr_data *data)
{
  bitmap_zero (data->pending, CPU_INTR_TABLE_SIZE);
  data->nr_pending = 0;
  list_init (&data->entries);
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
  slist_init (&ret->alert_list);
  ret->alnodes = NULL;
  ret->flags = flags;
  ret->tag = tag;
  cap_flow_intr_init (&ret->intr);

  int error = cap_flow_alloc_alerts (ret);
  if (error)
    {
      kmem_cache_free (&cap_flow_cache, ret);
      return (error);
    }

  *outp = ret;
  return (0);
}

/*
 * The byte following the plist node indicates whether the object is
 * an alert or a regular message with a thread blocking on it.
 */

static void
cap_mark_pnode_alert (struct plist_node *node)
{
  *(char *)(node + 1) = 1;
}

static void
cap_mark_pnode_msg (struct plist_node *node)
{
  *(char *)(node + 1) = 0;
}

static int
cap_pnode_is_alert (struct plist_node *node)
{
  return (*(char *)(node + 1));
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
cap_iters_init (struct cap_iters *it, struct ipc_msg *msg)
{
  ipc_iov_iter_init (&it->iov, msg->iovs, msg->iov_cnt);
  ipc_cap_iter_init (&it->cap, msg->caps, msg->cap_cnt);
  ipc_page_iter_init (&it->page, msg->pages, msg->page_cnt);
}

static void
cap_sender_init (struct cap_sender *sender, struct cap_flow *flow,
                 struct ipc_msg *src, struct ipc_msg *dst, uintptr_t tag)
{
  cap_ipc_msg_data_init (&sender->ipc_data, tag);
  sender->thread = thread_self ();
  sender->flow = flow;
  sender->handler = NULL;
  sender->result = 0;

  cap_iters_init (&sender->in_it, src);
  cap_iters_init (&sender->out_it, dst);
}

static void
cap_receiver_init (struct cap_receiver *recv, struct thread *self,
                   int cap, struct ipc_msg *msg)
{
  cap_ipc_msg_data_init (&recv->ipc_data, 0);
  recv->thread = self;
  recv->rcvid = (uint64_t)cap << 32;
  cap_iters_init (&recv->it, msg);
  recv->spurious = false;
}

/*
 * Transfer all 3 iterators between a local and a remote task.
 * Updates the metadata if succesful. Returns the number of
 * raw bytes transmitted on success; a negative errno value on failure.
 */

static ssize_t
cap_send_iters (struct task *task, struct cap_iters *r_it,
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

static void
cap_sender_receiver_step (struct cap_sender *sender, struct cap_receiver *recv)
{
  // Update counters and handler thread.
  sender->ipc_data.caps_sent += recv->ipc_data.caps_recv;
  sender->ipc_data.pages_sent += recv->ipc_data.pages_recv;
  sender->handler = recv->thread;

  // Complete the receive ID and set the tag.
  recv->rcvid |= sender->thread->kuid.id;
  recv->ipc_data.tag = sender->ipc_data.tag;

  // Fill in the rest of the metadata.
  recv->ipc_data.thread_id = sender->thread->kuid.id;
  recv->ipc_data.task_id = sender->thread->task->kuid.id;
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
  cap_mark_pnode_msg (&sender->node);
  // TODO: Priority inheritance.
  sender->sender_sched = *thread_get_real_sched_data(sender->thread);
}

static ssize_t
cap_sender_impl (struct cap_sender *sender, struct cap_flow *flow)
{
  struct cap_receiver *recv;

  {
    SPINLOCK_GUARD (&flow->lock);
    if (list_empty (&flow->receivers))
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

  ssize_t tmp = cap_send_iters (recv->thread->task, &recv->it, &sender->in_it,
                                IPC_COPY_TO, &recv->ipc_data);
  if (tmp < 0)
    return (cap_recv_putback (flow, recv, tmp));

  cap_sender_receiver_step (sender, recv);

  // Switch to handler thread and return result.
  sender->recv_sched = *thread_get_real_sched_data(recv->thread);
  thread_handoff (sender->thread, recv->thread, sender, &sender->sender_sched);
  return (sender->result);
}

static void
cap_flow_pop_alert_locked (struct cap_flow *flow, union cap_alert **outp)
{
  _Auto ret = slist_first_entry (&flow->alert_list, union cap_alert, snode);
  slist_remove (&flow->alert_list, NULL);
  *outp = ret;
}

static int
cap_flow_pop_alert (struct cap_flow *flow, int flags, union cap_alert **outp)
{
  if (unlikely (slist_empty (&flow->alert_list)))
    {
      if (!(flags & CAP_ALERT_BLOCK))
        return (-EAGAIN);

      spinlock_unlock (&flow->lock);

      struct slist tmp;
      _Auto node = cap_alert_alloc (&tmp);

      spinlock_lock (&flow->lock);
      if (unlikely (!slist_empty (&flow->alert_list)))
        {
          /*
           * Someone added a node in the interim. Make sure to put it back in
           * the cache. However, since we can't hold a spinlock during
           * deallocations, pop one of the freshly allocated alerts first.
           */
          cap_flow_pop_alert_locked (flow, outp);
          spinlock_unlock (&flow->lock);
          kmem_cache_free (&cap_alert_cache, node);
          spinlock_lock (&flow->lock);
          return (0);
        }

      cap_flow_push_alnode (flow, &tmp, node);
    }

  cap_flow_pop_alert_locked (flow, outp);
  return (0);
}

static ssize_t
cap_send_small (struct cap_receiver *recv, const void *buf,
                size_t size, uint32_t flags)
{
  _Auto iov = IOVEC (buf, size);
  ssize_t rv = ipc_bcopyv (recv->thread->task, recv->it.iov.begin,
                           recv->it.iov.end, &iov, 1, IPC_COPY_TO);

  if (unlikely (rv < 0))
    return (rv);

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
    return (-E2BIG);

  struct cap_flow *flow;

  if (cap->type == CAP_TYPE_CHANNEL)
    {
      flow = ((struct cap_channel *)cap)->flow;

      if (! flow)
        return (-EINVAL);
    }
  else if (cap->type == CAP_TYPE_FLOW)
    flow = (struct cap_flow *)cap;
  else
    return (-EBADF);

  union cap_alert *alert;
  char abuf[CAP_ALERT_SIZE];

  /*
   * Copy into a temporary buffer, since the code below may otherwise
   * generate a page fault while holding a spinlock.
   */
  memset (abuf, 0, sizeof (abuf));
  memcpy (abuf, buf, MIN (CAP_ALERT_SIZE, size));

  struct cap_receiver *recv;

  {
    SPINLOCK_GUARD (&flow->lock);
    int error = cap_flow_pop_alert (flow, flags, &alert);

    if (error)
      return (error);
    else if (list_empty (&flow->receivers))
      {
        memcpy (alert->payload + 1, abuf, size);
        plist_node_init (&alert->pnode, priority);
        plist_add (&flow->senders, &alert->pnode);
        cap_mark_pnode_alert (&alert->pnode);

        return (0);
      }

    recv = list_pop (&flow->receivers, typeof (*recv), node);
  }

  return (cap_send_small (recv, abuf, sizeof (abuf), 0));
}

static struct cap_sender*
cap_thread_sender (struct thread *thr)
{
  return ((void *)thread_wchan_addr (thr));
}

/*
 * A receive ID is a 64-bit integer, composed of a capability index
 * and a thread ID. When decoding it, the following invariants must apply:
 *
 * - Both the capability index and thread ID must reflect valid entities.
 * - The thread must be either sending a message or awaiting a reply.
 * - The capability described by the index must be equal to the one the
     thread sent a message to.
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
  if (!sender || sender->flow != flow)
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
      thread_setscheduler (self, sender->recv_sched.sched_policy,
                           sender->recv_sched.global_priority);
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
cap_recv_small (struct cap_receiver *recv, const void *buf, size_t size)
{
  _Auto base = recv->it.iov.begin;
  _Auto end = base + recv->it.iov.end;

  for (; base < end && size; ++base)
    {
      size_t len = MIN (size, base->iov_len);
      memcpy (base->iov_base, buf, len);
      buf = (const char *)buf + len;
      size -= len;
    }
}

static void
cap_recv_intr (struct cap_receiver *recv, struct cap_flow *flow)
{
  int irq = bitmap_find_first (flow->intr.pending, CPU_INTR_TABLE_SIZE);
  bitmap_clear (flow->intr.pending, irq);
  --flow->intr.nr_pending;

  spinlock_unlock (&flow->lock);
  cap_recv_small (recv, &irq, sizeof (irq));
  recv->ipc_data.flags |= IPC_MSG_INTR;
}

static rcvid_t
cap_receiver_impl (struct cap_receiver *recv, struct cap_flow *flow)
{
  struct plist_node *pnode = NULL;
  cap_rcvid_detach (recv->thread);

retry:
  spinlock_lock (&flow->lock);
  if (flow->intr.nr_pending)
    {
      cap_recv_intr (recv, flow);
      return (0);
    }
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

  spinlock_unlock (&flow->lock);
  if (cap_pnode_is_alert (pnode))
    {
      _Auto alert = plist_entry (pnode, union cap_alert, pnode);
      cap_recv_small (recv, &alert->payload[1], CAP_ALERT_SIZE);
      SPINLOCK_GUARD (&flow->lock);
      slist_insert_head (&flow->alert_list, &alert->snode);
      return (0);
    }

  _Auto sender = plist_entry (pnode, struct cap_sender, node);
  ssize_t tmp = cap_send_iters (sender->thread->task, &sender->in_it,
                                &recv->it, IPC_COPY_FROM, &recv->ipc_data);

  if (tmp < 0)
    {
      sender->result = tmp;
      thread_wakeup (sender->thread);
      if (-tmp == EPERM || -tmp == ENXIO)
        // The error was in the sender's buffers. Back to sleep.
        goto retry;

      return (tmp);
    }

  cap_sender_receiver_step (sender, recv);

  // Inherit the scheduling context and return.
  sender->recv_sched = *thread_get_real_sched_data(recv->thread);
  thread_adopt (sender->thread, recv->thread);
  return (recv->rcvid);
}

ssize_t
(cap_send_msg) (struct cap_base *cap, const struct ipc_msg *src,
                struct ipc_msg *dst, struct ipc_msg_data *data)
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
        return (thread_handle_msg (((struct cap_thread *)cap)->thread,
                                   (struct ipc_msg *)src, dst, data));
      case CAP_TYPE_TASK:
        return (task_handle_msg (((struct cap_task *)cap)->task,
                                 (struct ipc_msg *)src, dst, data));
      case CAP_TYPE_KERNEL:
        // TODO: Implement.
      default:
        return (-EINVAL);
    }

  struct cap_sender sender;
  cap_sender_init (&sender, flow, (struct ipc_msg *)src, dst, tag);

  ssize_t ret = cap_sender_impl (&sender, flow);
  if (ret >= 0 && data)
    *data = sender.ipc_data;

  return (ret);
}

static void
cap_base_rel_safe (void *ptr)
{
  _Auto cap = *(struct cap_base **)ptr;
  if (cap)
    cap_base_rel (cap);
}

rcvid_t
cap_recv_msg (int capx, struct ipc_msg *msg, struct ipc_msg_data *data)
{
  _Auto self = thread_self ();
  _Auto cap CLEANUP (cap_base_rel_safe) = cspace_get (&self->task->caps, capx);
  struct cap_flow *flow;

  if (! cap)
    return (-EBADF);
  else if (cap->type == CAP_TYPE_FLOW)
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
  cap_receiver_init (&rcv, self, capx, msg);

  rcvid_t ret = cap_receiver_impl (&rcv, flow);
  if (ret >= 0 && data)
    *data = rcv.ipc_data;

  return (ret);
}

int
cap_reply_msg (rcvid_t rcvid, const struct ipc_msg *msg, int rv)
{
  int error;
  struct thread *self = thread_self ();
  _Auto sender = cap_rcvid_acq_rel_sender (self, rcvid, &error);

  if (! sender)
    return (error);
  else if (rv >= 0)
    {
      struct cap_iters l_it;
      cap_iters_init (&l_it, (struct ipc_msg *)msg);

      ssize_t bytes = cap_send_iters (sender->thread->task,
                                      &sender->out_it, &l_it,
                                      IPC_COPY_TO, &sender->ipc_data);
      if (bytes >= 0)
        {
          sender->result = sender->ipc_data.nbytes;
          sender->ipc_data.task_id = self->task->kuid.id;
          sender->ipc_data.thread_id = self->kuid.id;
        }
      else
        sender->result = bytes;
    }
  else
    sender->result = rv;

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
cap_push_pull_msg (struct cap_sender *sender, struct ipc_msg *msg,
                   struct ipc_msg_data *mdata, int dir,
                   struct cap_iters *it)
{
  struct cap_iters l_it;
  cap_iters_init (&l_it, msg);

  cap_ipc_msg_data_init (mdata, sender->ipc_data.tag);
  _Auto task = sender->thread->task;

  ssize_t bytes = cap_send_iters (task, it, &l_it, dir, mdata);
  if (bytes >= 0)
    {
      mdata->thread_id = sender->thread->kuid.id;
      mdata->task_id = task->kuid.id;
    }

  return (bytes);
}

ssize_t
cap_pull_msg (rcvid_t rcvid, struct ipc_msg *msg, struct ipc_msg_data *mdata)
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
  ssize_t ret = cap_push_pull_msg (sender, msg, mdata,
                                   IPC_COPY_FROM, &sender->in_it);

  if (ret >= 0)
    {
      sender->ipc_data.pages_sent += mdata->pages_recv;
      sender->ipc_data.caps_sent += mdata->caps_recv;
    }

  return (ret);
}

ssize_t
cap_push_msg (rcvid_t rcvid, const struct ipc_msg *msg,
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
  ssize_t ret = cap_push_pull_msg (sender, (struct ipc_msg *)msg, &out_data,
                                   IPC_COPY_TO, &sender->out_it);

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

static int
cap_redirect_task_thread (struct cap_sender *sender, void *obj, int is_thr)
{
  struct ipc_msg src, dst;
  struct ipc_msg_data mdata;

#define cap_init_msg(msg, it)   \
  ((msg)->iovs = (it)->iov.begin,   \
   (msg)->iov_cnt = (it)->iov.end,   \
   (msg)->pages = (it)->page.begin,   \
   (msg)->page_cnt = (it)->page.end,   \
   (msg)->caps = (it)->cap.begin,   \
   (msg)->cap_cnt = (it)->cap.end)

  cap_init_msg (&src, &sender->in_it);
  cap_init_msg (&dst, &sender->out_it);

#undef cap_init_msg
  return (is_thr ?
          thread_handle_msg (((struct cap_thread *)obj)->thread, &src,
                             &dst, &mdata) :
          task_handle_msg (((struct cap_task *)obj)->task, &src,
                           &dst, &mdata));
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

  cap_reset_iter (&sender->in_it);
  cap_reset_iter (&sender->out_it);

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
        return (cap_redirect_task_thread (sender, cap,
                                          cap->type == CAP_TYPE_THREAD));
      case CAP_TYPE_KERNEL:
        // XXX: Implement.
        return (-EINVAL);
    }

  spinlock_lock (&flow->lock);
  cap_sender_enqueue (sender, flow);

  if (list_empty (&flow->receivers))
    {
      spinlock_unlock (&flow->lock);
      return (0);
    }

  _Auto recv = list_pop (&flow->receivers, struct cap_receiver, node);
  spinlock_unlock (&flow->lock);

  recv->spurious = true;
  thread_wakeup (recv->thread);
  return (0);
}

#undef cap_reset_iter
#undef cap_reset_iter_single

static int
cap_notify_intr (struct list *node, uint32_t irq)
{
  _Auto ep = list_entry (node, struct cap_intr_entry, intr_node);
  _Auto flow = ep->flow;
  struct cap_receiver *recv;

  {
    SPINLOCK_GUARD (&flow->lock);
    if (bitmap_test (flow->intr.pending, irq))
      return (EAGAIN);
    else if (list_empty (&flow->receivers))
      {
        bitmap_set (flow->intr.pending, irq);
        ++flow->intr.nr_pending;
        return (EINPROGRESS);
      }

    recv = list_pop (&flow->receivers, typeof (*recv), node);
  }

  ssize_t rv = cap_send_small (recv, &ep->irq, sizeof (ep->irq), IPC_MSG_INTR);
  return (rv < 0 ? 0 : EINPROGRESS);
}

static int
cap_handle_intr (void *arg)
{
  struct list *list = arg;
  assert (list >= &cap_intr_handlers[0] &&
          list <= &cap_intr_handlers[ARRAY_SIZE (cap_intr_handlers) - 1]);

  uint32_t irq = (uint32_t)(list - &cap_intr_handlers[0]) + CPU_EXC_INTR_FIRST;
  int ret = EAGAIN;

  list_rcu_for_each (list, tmp)
    {
      int rv = cap_notify_intr (tmp, irq);
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
cap_intr_rem (uint32_t intr, struct list *node, bool eoi)
{
  adaptive_lock_acquire (&cap_intr_lock);
  list_rcu_remove (node);

  if (list_empty (&cap_intr_handlers[intr - CPU_EXC_INTR_FIRST]))
    {
      if (eoi)
        intr_eoi (intr);
      intr_unregister (intr, cap_handle_intr);
    }

  adaptive_lock_release (&cap_intr_lock);
  rcu_wait ();
  return (0);
}

static struct cap_intr_entry*
cap_find_intr (struct cap_flow *flow, uint32_t irq)
{
  struct cap_intr_entry *tmp;

  list_for_each_entry (&flow->intr.entries, tmp, cap_node)
    if (tmp->irq == irq)
      return (tmp);

  return (NULL);
}

int
cap_intr_register (struct cap_flow *flow, uint32_t irq)
{
  if (irq < CPU_EXC_INTR_FIRST || irq > CPU_EXC_INTR_LAST)
    return (EINVAL);

  struct cap_intr_entry *ep = kmem_cache_alloc (&cap_misc_cache);
  if (! ep)
    return (ENOMEM);

  list_node_init (&ep->cap_node);
  list_node_init (&ep->intr_node);
  ep->irq = irq;
  ep->flow = flow;

  int error = cap_intr_add (irq, &ep->intr_node);
  if (error)
    {
      kmem_cache_free (&cap_misc_cache, ep);
      return (error);
    }

  spinlock_lock (&flow->lock);
  if (cap_find_intr (flow, irq))
    {
      spinlock_unlock (&flow->lock);
      cap_intr_rem (irq, &ep->intr_node, false);
      kmem_cache_free (&cap_misc_cache, ep);
      return (EALREADY);
    }

  list_insert_tail (&flow->intr.entries, &ep->cap_node);
  spinlock_unlock (&flow->lock);
  return (0);
}

int
cap_intr_unregister (struct cap_flow *flow, uint32_t irq)
{
  CPU_INTR_GUARD ();

  spinlock_lock (&flow->lock);
  _Auto entry = cap_find_intr (flow, irq);
  spinlock_unlock (&flow->lock);

  return (!entry ? EINVAL :
          cap_intr_rem (irq, &entry->intr_node,
                        bitmap_test (flow->intr.pending, irq)));
}

int
cap_intr_eoi (struct cap_flow *flow, uint32_t irq)
{
  SPINLOCK_GUARD (&flow->lock);
  if (bitmap_test (flow->intr.pending, irq))
    {
      bitmap_clear (flow->intr.pending, irq);
      --flow->intr.nr_pending;
    }
  else if (!cap_find_intr (flow, irq))
    return (EINVAL);

  intr_eoi (irq);
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
                              SZ (kernel), SZ (intr_entry));

  kmem_cache_init (&cap_misc_cache, "cap_misc", size, 0, NULL, 0);
  kmem_cache_init (&cap_flow_cache, "cap_flow",
                   sizeof (struct cap_flow), 0, NULL, 0);
  kmem_cache_init (&cap_alert_cache, "cap_alert",
                   sizeof (struct cap_alert_node), 0, NULL, 0);

  adaptive_lock_init (&cap_intr_lock);
  for (size_t i = 0; i < ARRAY_SIZE (cap_intr_handlers); ++i)
    list_init (&cap_intr_handlers[i]);

  return (0);
}

INIT_OP_DEFINE (cap_setup,
                INIT_OP_DEP (intr_setup, true),
                INIT_OP_DEP (kmem_setup, true));
