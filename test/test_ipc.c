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
 * This test module tests IPC between threads of different tasks.
 */

#include <assert.h>
#include <stdio.h>

#include <kern/ipc.h>
#include <kern/semaphore.h>
#include <kern/spinlock.h>
#include <kern/task.h>
#include <kern/thread.h>

#include <test/test.h>

#include <vm/map.h>
#include <vm/page.h>

#define TEST_IPC_DATA_SIZE   128

struct test_ipc_data
{
  struct semaphore send_sem;
  struct semaphore recv_sem;
  struct ipc_iov_iter *iovs;
  struct ipc_vme_iter *pgs;
  struct task *receiver;
  ssize_t len;
  int nr_pages;
};

struct test_ipc_vars
{
  char buf[TEST_IPC_DATA_SIZE];
  struct iovec iovs[2];
  struct ipc_msg_vme mp;
};

static struct test_ipc_data test_data;

static void
test_ipc_sender (void *arg)
{
  _Auto data = (struct test_ipc_data *)arg;
  struct test_ipc_vars *vars;
  int error = vm_map_anon_alloc ((void **)&vars,
                                 vm_map_self (), PAGE_SIZE * 2);
  assert (! error);
  memset (vars->buf, '-', sizeof (vars->buf));
  size_t half = TEST_IPC_DATA_SIZE / 2;
  vars->iovs[0] = IOVEC (vars->buf, half);
  vars->iovs[1] = IOVEC (vars->buf + half, half);

  struct ipc_iov_iter it;
  ipc_iov_iter_init (&it, vars->iovs, 2);
  assert (!ipc_iov_iter_empty (&it));

  struct ipc_vme_iter pg;
  vars->mp = (struct ipc_msg_vme)
    {
      .addr = (uintptr_t)vars + PAGE_SIZE,
      .size = PAGE_SIZE,
      .prot = VM_PROT_RDWR,
      .max_prot = VM_PROT_RDWR,
    };

  ipc_vme_iter_init (&pg, &vars->mp, 1);
  *(char *)vars->mp.addr = '+';

  semaphore_wait (&data->send_sem);
  data->len = ipc_iov_iter_copy (data->receiver, data->iovs,
                                 &it, IPC_COPY_TO);
  data->nr_pages = ipc_vme_iter_copy (data->receiver, data->pgs,
                                      &pg, IPC_COPY_TO);
  semaphore_post (&data->recv_sem);
  semaphore_wait (&data->send_sem);
}

static void
test_ipc_receiver (void *arg)
{
  _Auto data = (struct test_ipc_data *)arg;
  struct
    {
      char buf[TEST_IPC_DATA_SIZE - 10];
      struct ipc_msg_vme mp;
    } *vars;

  int error = vm_map_anon_alloc ((void **)&vars, vm_map_self (), 1);
  assert (! error);
  vars->mp.addr = PAGE_SIZE * 10;

  struct ipc_iov_iter it;
  struct ipc_vme_iter pg;

  ipc_iov_iter_init_buf (&it, vars->buf, sizeof (vars->buf));
  assert (!ipc_iov_iter_empty (&it));

  ipc_vme_iter_init (&pg, &vars->mp, 1);
  assert (ipc_vme_iter_size (&pg) > 0);

  data->iovs = &it;
  data->pgs = &pg;
  data->receiver = task_self ();

  semaphore_post (&data->send_sem);
  semaphore_wait (&data->recv_sem);

  assert (data->len == sizeof (vars->buf));
  assert (vars->buf[0] == '-');
  assert (vars->buf[sizeof (vars->buf) - 1] == '-');
  assert (data->nr_pages == 1);
  assert (*(char *)vars->mp.addr == '+');

  *(char *)vars->mp.addr = '*';
  semaphore_post (&data->send_sem);
}

TEST_DEFERRED (ipc)
{
  _Auto data = &test_data;
  semaphore_init (&data->send_sem, 0, 0xff);
  semaphore_init (&data->recv_sem, 0, 0xff);

  struct thread *sender, *receiver;
  int error = test_util_create_thr (&sender, test_ipc_sender,
                                    data, "ipc_sender");
  assert (! error);

  error = test_util_create_thr (&receiver, test_ipc_receiver,
                                data, "ipc_receiver");
  assert (! error);

  thread_join (sender);
  thread_join (receiver);
  return (TEST_OK);
}
