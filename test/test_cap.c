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

#include <assert.h>
#include <stdio.h>

#include <kern/clock.h>
#include <kern/cspace.h>
#include <kern/intr.h>
#include <kern/semaphore.h>
#include <kern/task.h>
#include <kern/thread.h>

#include <test/test.h>

#include <vm/map.h>

#define TEST_CAP_CHANNEL_TAG   ((uintptr_t)1234)

struct test_cap_data
{
  uintptr_t tag;
  struct cap_channel *ch;
  struct task *receiver;
  struct semaphore recv_sem;
  struct semaphore send_sem;
};

struct test_cap_vars
{
  struct ipc_msg msg;
  struct ipc_msg_data mdata;
  char buf[16];
  uint32_t bufsize;
  struct iovec iov;
  struct ipc_msg_page mpage;
  struct ipc_msg_cap mcap;
  struct cap_thread_info info;
};

static struct test_cap_data test_cap_data;

static int
test_cap_alloc_task (struct task *task)
{
  struct cap_task *ctask;
  int error = cap_task_create (&ctask, task);
  assert (! error);

  int capx = cap_intern (ctask, 0);
  assert (capx >= 0);
  cap_base_rel (ctask);

  return (capx);
}

#if !defined (__LP64__) && defined (__i386__)
__attribute__ ((regparm (2)))
#endif
static void
test_cap_entry (struct ipc_msg *msg, struct ipc_msg_data *mdata)
{
  assert (mdata->nbytes > 0);
  assert (mdata->pages_recv == 1);
  assert (mdata->caps_recv == 1);
  assert (mdata->tag == TEST_CAP_CHANNEL_TAG);
  assert (mdata->task_id == task_id (thread_self()->task));
  assert (mdata->thread_id == thread_id (thread_self ()));

  _Auto vars = structof (msg, struct test_cap_vars, msg);
  ssize_t nb = cap_pull_bytes (vars->buf, vars->bufsize, mdata);

  assert (nb == (ssize_t)vars->bufsize);
  assert (memcmp (vars->buf, "hello", 5) == 0);

  struct vm_map_entry entry;
  int error = vm_map_lookup (vm_map_self (), vars->mpage.addr, &entry);

  assert (! error);
  assert (VM_MAP_PROT (entry.flags) == VM_PROT_READ);
  assert (*(char *)vars->mpage.addr == 'x');

  vm_map_entry_put (&entry);

  _Auto cap = cspace_get (cspace_self (), vars->mcap.cap);
  assert (cap != NULL);
  assert (cap->type == CAP_TYPE_TASK);
  assert (((struct cap_task *)cap)->task == thread_self()->task);
  cap_base_rel (cap);

  vars->bufsize = 'Z';

  void *mem;
  error = vm_map_anon_alloc (&mem, vm_map_self (), 101);
  assert (! error);

  _Auto mp = (struct ipc_msg_data *)mem + 1;
  nb = cap_push_bytes (&vars->bufsize, sizeof (vars->bufsize), mp);
  assert (nb == sizeof (vars->bufsize));
  assert (mp->nbytes == nb);

  memset (mem, 'z', 100);
  vars->mpage.addr = (uintptr_t)mem;
  vars->mpage.size = PAGE_SIZE;
  vars->mcap.cap = test_cap_alloc_task (task_self ());
  vars->iov = IOVEC (memset (vars->buf, '?', sizeof (vars->buf)), 8);

  cap_reply_msg (&vars->msg, 0);
  panic ("cap_reply_msg returned");
}

static void
test_cap_receiver (void *arg)
{
  struct test_cap_data *data = arg;
  struct cap_flow *flow;

  data->tag = (uintptr_t)clock_get_time ();
  int error = cap_flow_create (&flow, 0, data->tag, (uintptr_t)test_cap_entry);
  assert (! error);

  error = cap_channel_create (&data->ch, flow, TEST_CAP_CHANNEL_TAG);
  assert (! error);

  _Auto page = vm_page_alloc (0, VM_PAGE_SEL_DIRECTMAP, VM_PAGE_KERNEL, 0);
  assert (page != NULL);

  vm_page_ref (page);

  struct test_cap_vars *vars;
  error = vm_map_anon_alloc ((void **)&vars, vm_map_self (), 1);
  assert (! error);

  {
    // Test that alerts are delivered in priority order.
    strcpy (vars->buf, "abcd");
    ssize_t rv = cap_send_alert (flow, vars->buf, 0, 0);
    assert (rv >= 0);

    strcpy (vars->buf, "1234");
    rv = cap_send_alert (flow, vars->buf, 0, 1);
    assert (rv >= 0);

    error = cap_recv_alert (flow, vars->buf, 0, &vars->mdata);
    assert (! error);
    assert (memcmp (vars->buf, "1234", 4) == 0);

    error = cap_recv_alert (flow, vars->buf, 0, &vars->mdata);
    assert (! error);
    assert (memcmp (vars->buf, "abcd", 4) == 0);
    assert (vars->mdata.task_id = task_id (thread_self()->task));
    assert (vars->mdata.thread_id = thread_id (thread_self ()));
  }

  vars->mpage = (struct ipc_msg_page) { .addr = PAGE_SIZE * 10 };
  vars->iov = IOVEC (&vars->bufsize, sizeof (vars->bufsize));
  vars->msg = (struct ipc_msg)
    {
      .size = sizeof (struct ipc_msg),
      .iovs = &vars->iov,
      .iov_cnt = 1,
      .pages = &vars->mpage,
      .page_cnt = 1,
      .caps = &vars->mcap,
      .cap_cnt = 1,
    };

  error = cap_flow_add_port (flow, (char *)vm_page_direct_ptr (page) +
                             PAGE_SIZE, PAGE_SIZE, &vars->msg,
                             &vars->mdata, &vars->info);
  assert (! error);

  semaphore_post (&data->send_sem);
  semaphore_wait (&data->recv_sem);
  vm_page_unref (page);
}

static void
test_cap_sender (void *arg)
{
  struct test_cap_data *data = arg;
  semaphore_wait (&data->send_sem);

  void *mem;
  int error = vm_map_anon_alloc (&mem, vm_map_self (), PAGE_SIZE * 2);
  assert (! error);

  struct
    {
      struct ipc_msg_page mpage;
      char buf[6];
      uint32_t bufsize;
      struct iovec iovecs[2];
      struct ipc_msg msg;
      struct ipc_msg_data mdata;
      struct ipc_msg_cap mcap;
    } *vars = (void *)((char *)mem + PAGE_SIZE);

  vars->mpage = (struct ipc_msg_page)
    {
      .addr = (uintptr_t)memset (mem, 'x', PAGE_SIZE),
      .prot = VM_PROT_READ,
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
      .pages = &vars->mpage,
      .page_cnt = 1,
      .caps = &vars->mcap,
      .cap_cnt = 1,
    };

  ssize_t nb = cap_send_msg (data->ch, &vars->msg, &vars->msg, &vars->mdata);

  assert (nb > 0);
  assert (vars->bufsize == 'Z');
  assert (memcmp (vars->buf, "?????", 5) == 0);
  assert (*(char *)vars->mpage.addr == 'z');
  assert (vars->mdata.pages_sent == 1);
  assert (vars->mdata.pages_recv == 1);
  assert (vars->mdata.caps_sent == 1);
  assert (vars->mdata.caps_recv == 1);

  semaphore_post (&data->recv_sem);
}

static void
test_cap_misc (void *arg __unused)
{
  struct cap_task *ctask;
  int error = cap_task_create (&ctask, task_self ());
  assert (! error);

  struct
    {
      struct task_ipc_msg task_msg;
      struct thread_ipc_msg thr_msg;
      BITMAP_DECLARE (cpumap, CONFIG_MAX_CPUS);
    } *vars;

  error = vm_map_anon_alloc ((void **)&vars, vm_map_self (), sizeof (*vars));
  assert (! error);

  vars->task_msg.op = TASK_IPC_GET_NAME;
  ssize_t rv = cap_send_bytes (ctask, &vars->task_msg, sizeof (vars->task_msg),
                               &vars->task_msg, sizeof (vars->task_msg));

  assert (rv == 0);
  assert (strcmp (vars->task_msg.name, "cap_misc") == 0);

  vars->task_msg.op = TASK_IPC_SET_NAME;
  strcpy (vars->task_msg.name, "new_name");

  rv = cap_send_bytes (ctask, &vars->task_msg, sizeof (vars->task_msg), 0, 0);
  assert (rv == 0);
  assert (strcmp (task_self()->name, "new_name") == 0);

  cap_base_rel (ctask);

  struct cap_thread *cthread;
  error = cap_thread_create (&cthread, thread_self ());

  vars->thr_msg.op = THREAD_IPC_GET_NAME;
  rv = cap_send_bytes (cthread, &vars->thr_msg, sizeof (vars->thr_msg),
                       &vars->thr_msg, sizeof (vars->thr_msg));
  assert (rv == 0);
  assert (strcmp (vars->thr_msg.name, "cap_misc/0") == 0);

  thread_pin ();
  vars->thr_msg.op = THREAD_IPC_GET_AFFINITY;
  vars->thr_msg.cpumap.map = vars->cpumap;
  vars->thr_msg.cpumap.size = sizeof (vars->cpumap);

  rv = cap_send_bytes (cthread, &vars->thr_msg, sizeof (vars->thr_msg),
                       &vars->thr_msg, sizeof (vars->thr_msg));
  assert (rv == 0);
  assert (bitmap_test (vars->cpumap, cpu_id ()));
  thread_unpin ();

  cap_base_rel (cthread);
}

TEST_DEFERRED (cap)
{
  _Auto data = &test_cap_data;

  semaphore_init (&data->send_sem, 0, 0xff);
  semaphore_init (&data->recv_sem, 0, 0xff);

  struct thread *sender, *receiver, *misc;
  int error = test_util_create_thr (&sender, test_cap_sender,
                                    data, "cap_sender");
  assert (! error);

  error = test_util_create_thr (&receiver, test_cap_receiver,
                                data, "cap_receiver");

  error = test_util_create_thr (&misc, test_cap_misc, NULL, "cap_misc");

  thread_join (sender);
  thread_join (receiver);
  thread_join (misc);

  return (TEST_OK);
}
