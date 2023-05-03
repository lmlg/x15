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

struct test_cap_data
{
  struct semaphore send_sem;
  struct semaphore recv_sem;
  struct task *sender;
  struct task *receiver;
  int sender_capx;
  uintptr_t sender_tag;
};

static struct test_cap_data test_cap_data;

static int
test_cap_alloc_task (void)
{
  struct cap_task *ctask;
  int error = cap_task_create (&ctask, task_self ());
  assert (! error);

  int capx = cap_intern (ctask, 0);
  assert (capx >= 0);
  cap_base_rel (ctask);
  return (capx);
}

static void
test_cap_sender (void *arg)
{
  struct test_cap_data *data = arg;
  struct cap_flow *flow;

  data->sender_tag = (uintptr_t)clock_get_time ();
  int error = cap_flow_create (&flow, 0, data->sender_tag);

  assert (! error);
  data->sender_capx = cap_intern (flow, 0);
  assert (data->sender_capx >= 0);

  struct
    {
      uint64_t _alert_data;
      struct ipc_msg_data _mdata;
      char _buf[16];
      uint32_t _bufsize;
      struct iovec _iov;
      struct ipc_msg_page _mpage;
      struct ipc_msg_cap _mcap;
      struct ipc_msg _msg;
    } *vars;

  error = vm_map_anon_alloc ((void **)&vars, vm_map_self (), sizeof (*vars));
  assert (! error);

#define alert_data   vars->_alert_data
#define mdata        vars->_mdata
#define buf          vars->_buf
#define bufsize      vars->_bufsize
#define iov          vars->_iov
#define mpage        vars->_mpage
#define mcap         vars->_mcap
#define msg          vars->_msg

  {
    // Test that alerts are delivered in priority order.
    alert_data = 0;
    ssize_t rv = cap_send_alert (flow, &alert_data, sizeof (alert_data), 0, 0);
    assert (rv >= 0);
    alert_data = 1;
    rv = cap_send_alert (flow, &alert_data, sizeof (alert_data), 0, 1);
    assert (rv >= 0);

    rcvid_t rcvid = cap_recv_bytes (data->sender_capx, &alert_data,
                                    sizeof (alert_data), &mdata);
    assert (rcvid == 0);
    assert (alert_data == 1);
    rcvid = cap_recv_bytes (data->sender_capx, &alert_data,
                            sizeof (alert_data), &mdata);
    assert (rcvid == 0);
    assert (alert_data == 0);
  }

  data->sender = task_self ();
  semaphore_post (&data->recv_sem);

  iov = IOVEC (&bufsize, sizeof (bufsize));

  mpage = (struct ipc_msg_page) { .addr = PAGE_SIZE * 10 };
  msg = (struct ipc_msg)
    {
      .size = sizeof (msg),
      .iovs = &iov,
      .iov_cnt = 1,
      .pages = &mpage,
      .page_cnt = 1,
      .caps = &mcap,
      .cap_cnt = 1
    };

  rcvid_t rcvid = cap_recv_msg (data->sender_capx, &msg, &mdata);

  assert (rcvid > 0);
  assert (mdata.pages_recv == 1);
  assert (mdata.caps_recv == 1);

  {
    ssize_t nb = cap_pull_bytes (rcvid, buf, bufsize, &mdata);
    assert (nb == (ssize_t)bufsize);
    assert (memcmp (buf, "hello", 5) == 0);
  }

  {
    struct vm_map_entry entry;
    error = vm_map_lookup (vm_map_self (), mpage.addr, &entry);

    assert (! error);
    assert (VM_MAP_PROT (entry.flags) == VM_PROT_READ);
    assert (*(char *)mpage.addr == 'x');

    vm_map_entry_put (&entry);
  }

  {
    struct cap_base *cap = cspace_get (cspace_self (), mcap.cap);
    assert (cap != NULL);
    assert (cap->type == CAP_TYPE_TASK);
    assert (((struct cap_task *)cap)->task == data->receiver);
    cap_base_rel (cap);
  }

  bufsize = 'Z';
  ssize_t nb = cap_push_bytes (rcvid, &bufsize, sizeof (bufsize), &mdata);
  assert (nb == sizeof (bufsize));

  void *mem;
  error = vm_map_anon_alloc (&mem, vm_map_self (), 101);
  assert (! error);
  memset (mem, 'z', 100);

  mpage.addr = (uintptr_t)mem;
  mpage.size = PAGE_SIZE;
  mcap.cap = test_cap_alloc_task ();

  iov = IOVEC (memset (buf, '?', sizeof (buf)), 8);
  error = cap_reply_msg (rcvid, &msg, 0);
  assert (! error);

#undef alert_data
#undef mdata
#undef buf
#undef bufsize
#undef iov
#undef mpage
#undef mcap
#undef msg
}

static void
test_cap_receiver (void *arg)
{
  struct test_cap_data *data = arg;
  semaphore_wait (&data->recv_sem);

  struct cap_channel *chp;
  int error = cap_flow_hook (&chp, data->sender, data->sender_capx);

  assert (! error);

  uintptr_t tag;
  error = cap_get_tag (chp, &tag);
  assert (! error);
  assert (tag == data->sender_tag);

  void *mem;
  error = vm_map_anon_alloc (&mem, vm_map_self (), 100);
  assert (! error);
  memset (mem, 'x', PAGE_SIZE);

  struct
    {
      struct ipc_msg_page _mpage;
      char _buf[6];
      uint32_t _bufsize;
      struct iovec _iovecs[2];
      struct ipc_msg _msg;
      struct ipc_msg_data _mdata;
      struct ipc_msg_cap _mcap;
    } *vars;

#define mpage     vars->_mpage
#define buf       vars->_buf
#define bufsize   vars->_bufsize
#define iovecs    vars->_iovecs
#define msg       vars->_msg
#define mdata     vars->_mdata
#define mcap      vars->_mcap

  error = vm_map_anon_alloc ((void **)&vars, vm_map_self (), sizeof (*vars));
  assert (! error);
  mpage = (struct ipc_msg_page)
    {
      .addr = (uintptr_t)mem,
      .prot = VM_PROT_READ,
      .size = PAGE_SIZE,
    };

  int capx = test_cap_alloc_task ();
  mcap = (struct ipc_msg_cap) { .cap = capx, .flags = 0 };
  strcpy (buf, "hello");
  bufsize = sizeof (buf) - 1;
  iovecs[0] = IOVEC (&bufsize, sizeof (bufsize));
  iovecs[1] = IOVEC (buf, bufsize);
  msg = (struct ipc_msg)
    {
      .size = sizeof (msg),
      .iovs = iovecs,
      .iov_cnt = 2,
      .pages = &mpage,
      .page_cnt = 1,
      .caps = &mcap,
      .cap_cnt = 1
    };

  data->receiver = task_self ();
  ssize_t bytes = cap_send_msg (chp, &msg, &msg, &mdata);

  assert (bytes == (ssize_t)(iovecs[0].iov_len + iovecs[1].iov_len));
  assert (bufsize == 'Z');
  assert (memcmp (buf, "?????", 5) == 0);
  assert (*(char *)mpage.addr == 'z');
  assert (mdata.pages_sent == 1);
  assert (mdata.pages_recv == 1);
  assert (mdata.caps_sent == 1);
  assert (mdata.caps_recv == 1);

  cap_base_rel (chp);

#undef mpage
#undef buf
#undef bufsize
#undef iovs
#undef msg
#undef mdata
#undef mcap
}

static void
test_cap_misc (void *arg __unused)
{
  struct cap_task *ctask;
  int error = cap_task_create (&ctask, task_self ());
  assert (! error);

  struct task_ipc_msg task_msg;

  task_msg.op = TASK_IPC_GET_NAME;
  ssize_t rv = cap_send_bytes (ctask, &task_msg, sizeof (task_msg),
                               &task_msg, sizeof (task_msg));

  assert (rv == 0);
  assert (strcmp (task_msg.name, "cap_misc") == 0);

  task_msg.op = TASK_IPC_SET_NAME;
  strcpy (task_msg.name, "new_name");

  rv = cap_send_bytes (ctask, &task_msg, sizeof (task_msg), NULL, 0);
  assert (rv == 0);
  assert (strcmp (task_self()->name, "new_name") == 0);

  cap_base_rel (ctask);

  struct cap_thread *cthread;
  error = cap_thread_create (&cthread, thread_self ());

  struct thread_ipc_msg thr_msg;

  thr_msg.op = THREAD_IPC_GET_NAME;
  rv = cap_send_bytes (cthread, &thr_msg, sizeof (thr_msg),
                       &thr_msg, sizeof (thr_msg));
  assert (rv == 0);
  assert (strcmp (thr_msg.name, "cap_misc/0") == 0);

  struct cpumap *cpumap;
  error = cpumap_create (&cpumap);
  assert (! error);
  cpumap_zero (cpumap);

  thread_pin ();
  thr_msg.op = THREAD_IPC_GET_AFFINITY;
  thr_msg.cpumap.map = cpumap->cpus;
  thr_msg.cpumap.size = sizeof (cpumap->cpus);

  rv = cap_send_bytes (cthread, &thr_msg, sizeof (thr_msg),
                       &thr_msg, sizeof (thr_msg));
  assert (rv == 0);
  assert (cpumap_test (cpumap, cpu_id ()));
  thread_unpin ();

  cpumap_destroy (cpumap);
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
