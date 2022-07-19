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
 * This test module tests page faults and the retrieval of page data
 * from VM objects.
 */

#include <assert.h>
#include <stdio.h>
#include <uio.h>

#include <kern/ipc.h>
#include <kern/semaphore.h>
#include <kern/spinlock.h>
#include <kern/task.h>
#include <kern/thread.h>

#include <test/test.h>

#include <vm/map.h>

struct test_ipc_data
{
  struct semaphore send_sem;
  struct semaphore recv_sem;
  char buf1[16];
  char buf2[24];
  struct ipc_iterator *out;
  struct thread *receiver;
  ssize_t len;
};

static struct test_ipc_data test_data;

static void
test_ipc_create (void (*fn) (void *), void *arg,
                 const char *task_name,
                 struct thread **thrp)
{
  struct task *task;
  int error = task_create (&task, task_name);
  assert (! error);

  char tname[32];
  sprintf (tname, "%s/0", task_name);

  struct thread_attr attr;
  thread_attr_init (&attr, tname);
  thread_attr_set_task (&attr, task);

  error = thread_create (thrp, &attr, fn, arg);
  assert (! error);
}

static void
test_ipc_sender (void *arg)
{
  _Auto data = (struct test_ipc_data *)arg;
  struct iovec iovs[] =
    {
      { .iov_base = data->buf1, .iov_len = sizeof (data->buf1) },
      { .iov_base = data->buf2, .iov_len = sizeof (data->buf2) }
    };

  semaphore_wait (&data->send_sem);

  struct ipc_iterator input;
  ipc_iterator_init_iov (&input, iovs, ARRAY_SIZE (iovs));
  assert (ipc_iterator_valid (&input));

  data->len = ipc_copy_iter (&input, thread_self (),
                             data->out, data->receiver);

  semaphore_post (&data->recv_sem);
}

static void
test_ipc_receiver (void *arg)
{
  _Auto data = (struct test_ipc_data *)arg;
  char buf[64];
  struct ipc_iterator it;

  ipc_iterator_init_buf (&it, buf, sizeof (buf));
  assert (ipc_iterator_valid (&it));
  data->out = &it;
  data->receiver = thread_self ();

  semaphore_post (&data->send_sem);
  semaphore_wait (&data->recv_sem);

  assert (data->len == sizeof (data->buf1) + sizeof (data->buf2));
  assert (memcmp (data->buf1, buf, sizeof (data->buf1)) == 0);
  assert (memcmp (data->buf2, buf + sizeof (data->buf1),
                  sizeof (data->buf2)) == 0);
}

TEST_DEFERRED (ipc)
{
  _Auto data = &test_data;
  semaphore_init (&data->send_sem, 0, 0xff);
  semaphore_init (&data->recv_sem, 0, 0xff);

  memset (data->buf1, '-', sizeof (data->buf1));
  memset (data->buf2, '.', sizeof (data->buf2));

  struct thread *sender, *receiver;

  test_ipc_create (test_ipc_sender, data, "sender", &sender);
  test_ipc_create (test_ipc_receiver, data, "receiver", &receiver);

  thread_join (sender);
  thread_join (receiver);
  return (TEST_OK);
}
