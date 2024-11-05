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
 * This test module tests the capability API.
 */

#include <stdio.h>

#include <kern/clock.h>
#include <kern/cspace.h>
#include <kern/intr.h>
#include <kern/semaphore.h>
#include <kern/task.h>
#include <kern/thread.h>

#include <test/test.h>

#include <vm/map.h>
#include <vm/page.h>

#define TEST_CAP_CHANNEL_TAG   ((uintptr_t)1234)

struct test_cap_data
{
  uintptr_t tag;
  struct cap_channel *ch;
  struct task *receiver;
  struct semaphore recv_sem;
  struct semaphore send_sem;
  struct semaphore dead_sem;
};

struct test_cap_vars
{
  struct ipc_msg msg;
  struct ipc_msg_data mdata;
  char buf[16];
  uint32_t bufsize;
  struct iovec iov;
  struct ipc_msg_vme mvme[2];
  struct ipc_msg_cap mcap[2];
  struct cap_thread_info info;
  struct cap_kern_alert alert;
};

static struct test_cap_data test_cap_data;

static int
test_cap_alloc_task (struct task *task)
{
  struct cap_task *ctask;
  int error = cap_task_create (&ctask, task);
  test_assert_eq (error, 0);

  int capx = cap_intern (ctask, 0);
  test_assert_ge (capx, 0);
  cap_base_rel (ctask);

  return (capx);
}

#if !defined (__LP64__) && defined (__i386__)
__attribute__ ((regparm (2)))
#endif
static void
test_cap_entry (struct ipc_msg *msg, struct ipc_msg_data *mdata)
{
  test_assert_eq (mdata->bytes_recv, sizeof (uint32_t));
  test_assert_eq (mdata->vmes_recv, 1);
  test_assert_eq (mdata->caps_recv, 1);
  test_assert_eq (mdata->tag, TEST_CAP_CHANNEL_TAG);
  test_assert_eq (mdata->task_id, task_id (thread_self()->task));
  test_assert_eq (mdata->thread_id, thread_id (thread_self ()));

  _Auto vars = structof (msg, struct test_cap_vars, msg);
  ssize_t nb = cap_pull_bytes (vars->buf, vars->bufsize, mdata);

  test_assert_gt (nb, 0);
  test_assert_eq (nb, (ssize_t)vars->bufsize);
  test_assert_streq (vars->buf, "hello");

  _Auto entry = vm_map_find (vm_map_self (), vars->mvme[0].addr);
  test_assert_nonnull (entry);
  test_assert_eq (VM_MAP_PROT (entry->flags), VM_PROT_READ);
  test_assert_eq (*(char *)vars->mvme[0].addr, 'x');

  vm_map_entry_put (entry);

  _Auto cap = cspace_get (cspace_self (), vars->mcap[0].cap);
  test_assert_nonnull (cap);
  test_assert_eq (cap_type (cap), CAP_TYPE_TASK);
  test_assert_eq (((struct cap_task *)cap)->task, thread_self()->task);
  cap_base_rel (cap);

  vars->bufsize = 'Z';

  void *mem;
  int error = vm_map_anon_alloc (&mem, vm_map_self (), PAGE_SIZE * 2);
  test_assert_eq (error, 0);

  _Auto mp = (struct ipc_msg_data *)mem + 1;
  nb = cap_push_bytes (&vars->bufsize, sizeof (vars->bufsize), mp);
  test_assert_eq (nb, sizeof (vars->bufsize));
  test_assert_eq (mp->bytes_sent, nb);

  memset (mem, 'z', 100);
  vars->mvme[0].addr = (uintptr_t)mem;
  vars->mvme[0].size = vars->mvme[1].size = PAGE_SIZE;
  vars->mvme[1].addr = (uintptr_t)mem + PAGE_SIZE;

  vars->mcap[0].cap = test_cap_alloc_task (task_self ());
  vars->iov = IOVEC (memset (vars->buf, '?', sizeof (vars->buf)), 8);
  vars->msg.iov_cnt = 1;
  vars->msg.cap_cnt = 1;
  vars->msg.vme_cnt = 2;

  cap_reply_msg (&vars->msg, 0);
  panic ("cap_reply_msg returned");
}

static void
test_cap_receiver (void *arg)
{
  struct test_cap_data *data = arg;
  struct cap_flow *flow;

  data->receiver = task_self ();
  data->tag = (uintptr_t)clock_get_time ();
  int error = cap_flow_create (&flow, 0, data->tag, (uintptr_t)test_cap_entry);
  test_assert_eq (error, 0);

  error = cap_channel_create (&data->ch, flow, TEST_CAP_CHANNEL_TAG);
  test_assert_eq (error, 0);

  _Auto page = vm_page_alloc (0, VM_PAGE_SEL_DIRECTMAP, VM_PAGE_KERNEL, 0);
  test_assert_nonnull (page);

  vm_page_ref (page);

  struct test_cap_vars *vars;
  error = vm_map_anon_alloc ((void **)&vars, vm_map_self (), 1);
  test_assert_eq (error, 0);

  vars->mdata.size = sizeof (vars->mdata);

  {
    // Test that alerts are delivered in priority order.
    strcpy (vars->buf, "abcd");
    ssize_t rv = cap_send_alert (flow, vars->buf, 0, 0);
    test_assert_ge (rv, 0);

    strcpy (vars->buf, "1234");
    rv = cap_send_alert (flow, vars->buf, 0, 1);
    test_assert_ge (rv, 0);

    error = cap_recv_alert (flow, vars->buf, 0, &vars->mdata);
    test_assert_eq (error, 0);
    test_assert_streq (vars->buf, "1234");
    test_assert_eq (vars->mdata.task_id, task_id (thread_self()->task));
    test_assert_eq (vars->mdata.thread_id, thread_id (thread_self ()));
    test_assert_eq (vars->mdata.tag, data->tag);

    error = cap_recv_alert (flow, vars->buf, 0, &vars->mdata);
    test_assert_eq (error, 0);
    test_assert_streq (vars->buf, "abcd");
    test_assert_eq (vars->mdata.task_id, task_id (thread_self()->task));
    test_assert_eq (vars->mdata.thread_id, thread_id (thread_self ()));
    test_assert_eq (vars->mdata.tag, data->tag);
  }

  vars->mvme[0] = (struct ipc_msg_vme) { .addr = PAGE_SIZE * 10 };
  vars->iov = IOVEC (&vars->bufsize, sizeof (vars->bufsize));
  vars->msg = (struct ipc_msg)
    {
      .size = sizeof (struct ipc_msg),
      .iovs = &vars->iov,
      .iov_cnt = 1,
      .vmes = vars->mvme,
      .vme_cnt = 1,
      .caps = vars->mcap,
      .cap_cnt = 1,
    };

  vars->mdata.size = sizeof (vars->mdata);
  error = cap_flow_add_lpad (flow, (char *)vm_page_direct_ptr (page) +
                             PAGE_SIZE, PAGE_SIZE, &vars->msg,
                             &vars->mdata, &vars->info);
  test_assert_eq (error, 0);

  semaphore_post (&data->send_sem);
  semaphore_wait (&data->recv_sem);
  vm_page_unref (page);
  cap_base_rel (data->ch);

  // Test that we receive an alert on a channel closed.
  error = cap_recv_alert (flow, &vars->alert, 0, &vars->mdata);
  test_assert_eq (error, 0);
  test_assert_eq (vars->mdata.task_id, 0);
  test_assert_eq (vars->mdata.thread_id, 0);
  test_assert_eq (vars->alert.type, CAP_ALERT_CHAN_CLOSED);
  test_assert_eq (vars->alert.tag, TEST_CAP_CHANNEL_TAG);

  cap_base_rel (flow);
}

static void
test_cap_sender (void *arg)
{
  struct test_cap_data *data = arg;
  semaphore_wait (&data->send_sem);

  void *mem;
  int error = vm_map_anon_alloc (&mem, vm_map_self (), PAGE_SIZE * 2);
  test_assert_eq (error, 0);

  struct
    {
      struct ipc_msg_vme mvme;
      char buf[6];
      uint32_t bufsize;
      struct iovec iovecs[2];
      struct ipc_msg msg;
      struct ipc_msg_data mdata;
      struct ipc_msg_cap mcap;
      struct ipc_msg out_msg;
      struct ipc_msg_vme out_vme[2];
      struct ipc_msg_cap out_cap[2];
    } *vars = (void *)((char *)mem + PAGE_SIZE);

  vars->mdata.size = sizeof (vars->mdata);

  vars->mvme = (struct ipc_msg_vme)
    {
      .addr = (uintptr_t)memset (mem, 'x', PAGE_SIZE),
      .prot = VM_PROT_READ,
      .max_prot = VM_PROT_READ,
      .size = PAGE_SIZE
    };

  vars->mcap = (struct ipc_msg_cap)
    {
      .cap = test_cap_alloc_task (task_self ()),
      .flags = 0
    };

  strcpy (vars->buf, "hello");
  vars->bufsize = sizeof (vars->buf) - 1;
  vars->iovecs[0] = IOVEC (&vars->bufsize, sizeof (vars->bufsize));
  vars->iovecs[1] = IOVEC (vars->buf, vars->bufsize);

  vars->msg = (struct ipc_msg)
    {
      .size = sizeof (struct ipc_msg),
      .iovs = vars->iovecs,
      .iov_cnt = 2,
      .vmes = &vars->mvme,
      .vme_cnt = 1,
      .caps = &vars->mcap,
      .cap_cnt = 1,
    };

  vars->out_msg = (struct ipc_msg)
    {
      .size = sizeof (struct ipc_msg),
      .iovs = vars->iovecs,
      .iov_cnt = 2,
      .vmes = vars->out_vme,
      .vme_cnt = 2,
      .caps = vars->out_cap,
      .cap_cnt = 2
    };

  ssize_t nb = cap_send_msg (data->ch, &vars->msg,
                             &vars->out_msg, &vars->mdata);

  test_assert_eq (nb, (ssize_t)(sizeof (uint32_t) + sizeof (vars->buf) - 1));
  test_assert_eq (vars->bufsize, 'Z');
  test_assert_streq (vars->buf, "?????");
  test_assert_eq (*(char *)vars->out_vme[0].addr, 'z');
  test_assert_eq (vars->mdata.vmes_sent, 1);
  test_assert_eq (vars->mdata.vmes_recv, 2);
  test_assert_eq (vars->mdata.caps_sent, 1);
  test_assert_eq (vars->mdata.caps_recv, 1);
  test_assert_ne (vars->mdata.flags & IPC_MSG_TRUNC, 0);

  _Auto cap = cspace_get (cspace_self (), vars->out_cap[0].cap);
  test_assert_nonnull (cap);
  test_assert_eq (cap_type (cap), CAP_TYPE_TASK);
  test_assert_eq (((struct cap_task *)cap)->task, data->receiver);
  cap_base_rel (cap);

  semaphore_post (&data->recv_sem);
}

static void
test_cap_misc (void *arg __unused)
{
  struct cap_task *ctask;
  int error = cap_task_create (&ctask, task_self ());
  test_assert_eq (error, 0);

  struct
    {
      struct task_ipc_msg task_msg;
      struct thread_ipc_msg thr_msg;
      BITMAP_DECLARE (cpumap, CONFIG_MAX_CPUS);
    } *vars;

  error = vm_map_anon_alloc ((void **)&vars, vm_map_self (), sizeof (*vars));
  test_assert_eq (error, 0);

  vars->task_msg.op = TASK_IPC_GET_NAME;
  ssize_t rv = cap_send_bytes (ctask, &vars->task_msg, sizeof (vars->task_msg),
                               &vars->task_msg, sizeof (vars->task_msg));

  test_assert_eq (rv, 0);
  test_assert_streq (vars->task_msg.name, "cap_misc");

  vars->task_msg.op = TASK_IPC_SET_NAME;
  strcpy (vars->task_msg.name, "new_name");

  rv = cap_send_bytes (ctask, &vars->task_msg, sizeof (vars->task_msg), 0, 0);
  test_assert_eq (rv, 0);
  test_assert_streq (task_self()->name, "new_name");

  cap_base_rel (ctask);

  struct cap_thread *cthread;
  error = cap_thread_create (&cthread, thread_self ());

  vars->thr_msg.op = THREAD_IPC_GET_NAME;
  rv = cap_send_bytes (cthread, &vars->thr_msg, sizeof (vars->thr_msg),
                       &vars->thr_msg, sizeof (vars->thr_msg));

  test_assert_eq (rv, 0);
  test_assert_streq (vars->thr_msg.name, "cap_misc/0");

  thread_pin ();
  vars->thr_msg.op = THREAD_IPC_GET_AFFINITY;
  vars->thr_msg.cpumap.map = vars->cpumap;
  vars->thr_msg.cpumap.size = sizeof (vars->cpumap);

  rv = cap_send_bytes (cthread, &vars->thr_msg, sizeof (vars->thr_msg),
                       &vars->thr_msg, sizeof (vars->thr_msg));
  test_assert_eq (rv, 0);
  test_assert_ne (bitmap_test (vars->cpumap, cpu_id ()), 0);
  thread_unpin ();

  cap_base_rel (cthread);
}

static void
test_cap_dead_child (void *arg)
{
  semaphore_wait (arg);
}

static void
test_cap_dead_helper (void *arg)
{
  struct cap_flow *flow = arg;
  struct thread *thr;
  struct thread_attr attr;

  thread_attr_init (&attr, "cap_dead/2");
  thread_attr_set_detached (&attr);

  int error = thread_create (&thr, &attr, test_cap_dead_child,
                             &test_cap_data.dead_sem);
  test_assert_eq (error, 0);

  error = cap_thread_register (flow, thr);
  test_assert_eq (error, 0);

  error = cap_thread_unregister (flow, thr);
  test_assert_eq (error, 0);

  error = cap_thread_register (flow, thread_self ());
  test_assert_eq (error, 0);

  error = cap_task_register (flow, thread_self()->task);
  test_assert_eq (error, 0);

  test_cap_dead_child (&test_cap_data.dead_sem);
}

static void
test_cap_dead_notif (void *arg __unused)
{
  struct cap_flow *flow;
  int error = cap_flow_create (&flow, 0, 0, 0);
  test_assert_eq (error, 0);

  struct cap_channel *chan;
  error = cap_channel_create (&chan, flow, 1234);
  test_assert_eq (error, 0);

  int capx = cspace_add_free (cspace_self (), CAP (chan), CSPACE_WEAK);
  test_assert_ge (capx, 0);
  cap_base_rel (chan);

  int mark = 0;
  chan = (struct cap_channel *)cspace_get_all (cspace_self (), capx, &mark);
  test_assert_nonnull (chan);
  cap_base_rel (chan);

  if (mark)
    cap_base_rel (chan);

  struct
    {
      struct cap_kern_alert alert;
      char extra[16];
      struct ipc_msg_data mdata;
    } *buf;

  error = vm_map_anon_alloc ((void **)&buf, vm_map_self (), 1);
  test_assert_eq (error, 0);

  buf->mdata.size = sizeof (buf->mdata);
  error = cap_recv_alert (flow, &buf->alert, 0, &buf->mdata);
  test_assert_eq (error, 0);
  test_assert_eq (buf->mdata.thread_id, 0);
  test_assert_eq (buf->mdata.task_id, 0);
  test_assert_eq (buf->alert.type, CAP_ALERT_CHAN_CLOSED);
  test_assert_eq (buf->alert.tag, 1234);

  struct thread *thr;
  error = test_util_create_thr (&thr, test_cap_dead_helper, flow, "cap_dead");
  test_assert_eq (error, 0);

  int tsk_id = task_id (thr->task), thr_id = thread_id (thr);
  int got_task = 0, got_thr = 0;

  semaphore_post (&test_cap_data.dead_sem);
  semaphore_post (&test_cap_data.dead_sem);
  thread_join (thr);

  error = cap_recv_alert (flow, &buf->alert, 0, &buf->mdata);
  test_assert_eq (error, 0);
  test_assert_eq (buf->mdata.thread_id, 0);
  test_assert_eq (buf->mdata.task_id, 0);

  if (buf->alert.type == CAP_ALERT_THREAD_DIED &&
      buf->alert.thread_id == thr_id)
    got_thr = 1;
  else if (buf->alert.type == CAP_ALERT_TASK_DIED &&
           buf->alert.task_id == tsk_id)
    got_task = 1;
  else
    panic ("got unexpected alert");

  error = cap_recv_alert (flow, &buf->alert, 0, &buf->mdata);
  test_assert_eq (error, 0);
  test_assert_eq (buf->mdata.thread_id, 0);
  test_assert_eq (buf->mdata.task_id, 0);

  if (buf->alert.type == CAP_ALERT_THREAD_DIED &&
      buf->alert.thread_id == thr_id)
    ++got_thr;
  else if (buf->alert.type == CAP_ALERT_TASK_DIED &&
           buf->alert.task_id == tsk_id)
    ++got_task;
  else
    panic ("got unexpected alert");

  test_assert_eq (got_thr, 1);
  test_assert_eq (got_task, 1);
}

TEST_DEFERRED (cap)
{
  _Auto data = &test_cap_data;

  semaphore_init (&data->send_sem, 0, 0xff);
  semaphore_init (&data->recv_sem, 0, 0xff);
  semaphore_init (&data->dead_sem, 0, 0xff);

  struct thread *sender, *receiver, *misc, *dead_notif;
  int error = test_util_create_thr (&sender, test_cap_sender,
                                    data, "cap_sender");
  test_assert_eq (error, 0);

  error = test_util_create_thr (&receiver, test_cap_receiver,
                                data, "cap_receiver");
  test_assert_eq (error, 0);

  error = test_util_create_thr (&misc, test_cap_misc, NULL, "cap_misc");
  test_assert_eq (error, 0);

  error = test_util_create_thr (&dead_notif, test_cap_dead_notif,
                                NULL, "cap_dead");

  thread_join (sender);
  thread_join (receiver);
  thread_join (misc);
  thread_join (dead_notif);

  return (TEST_OK);
}
