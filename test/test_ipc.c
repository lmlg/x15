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
  struct ipc_page_iter *pgs;
  struct task *receiver;
  ssize_t len;
  int nr_pages;
};

static struct test_ipc_data test_data;

static void
test_ipc_sender (void *arg)
{
  _Auto data = (struct test_ipc_data *)arg;
  void *ptr;
  int error = vm_map_anon_alloc (&ptr, vm_map_self (), PAGE_SIZE * 2);
  assert (! error);
  char *mem = memset (ptr, '-', TEST_IPC_DATA_SIZE);
  size_t half = TEST_IPC_DATA_SIZE / 2;

  struct iovec iovs[] =
    {
      IOVEC (mem, half), IOVEC (mem + half, half)
    };

  struct ipc_iov_iter it;
  ipc_iov_iter_init (&it, iovs, 2);
  assert (!ipc_iov_iter_empty (&it));

  struct ipc_page_iter pg;
  struct ipc_msg_page mp =
    { .addr = (uintptr_t)mem + PAGE_SIZE, .size = PAGE_SIZE,
      .prot = VM_PROT_RDWR };

  ipc_page_iter_init (&pg, &mp, 1);
  *(char *)mp.addr = '+';

  semaphore_wait (&data->send_sem);
  data->len = ipc_iov_iter_copy (data->receiver, data->iovs,
                                 &it, IPC_COPY_TO);
  data->nr_pages = ipc_page_iter_copy (data->receiver, data->pgs,
                                       &pg, IPC_COPY_TO);
  semaphore_post (&data->recv_sem);
  semaphore_wait (&data->send_sem);
}

static void
test_ipc_receiver (void *arg)
{
  _Auto data = (struct test_ipc_data *)arg;
  char buf[TEST_IPC_DATA_SIZE - 10];
  struct ipc_iov_iter it;
  struct ipc_page_iter pg;
  struct ipc_msg_page mp = { .addr = PAGE_SIZE * 10 };

  ipc_iov_iter_init_buf (&it, buf, sizeof (buf));
  assert (!ipc_iov_iter_empty (&it));

  ipc_page_iter_init (&pg, &mp, 1);

  data->iovs = &it;
  data->pgs = &pg;
  data->receiver = task_self ();

  semaphore_post (&data->send_sem);
  semaphore_wait (&data->recv_sem);

  assert (data->len == sizeof (buf));
  assert (buf[0] == '-');
  assert (buf[sizeof (buf) - 1] == '-');
  assert (data->nr_pages == 1);
  assert (*(char *)mp.addr == '+');

  *(char *)mp.addr = '*';
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
