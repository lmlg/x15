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
 * This test module tests the interrupt API.
 */

#include <assert.h>
#include <stdio.h>

#include <kern/capability.h>
#include <kern/intr.h>
#include <kern/semaphore.h>
#include <kern/task.h>

#include <vm/map.h>

#include <test/test.h>

#define TEST_INTR_FIRST   CPU_EXC_INTR_FIRST
#define TEST_INTR_LAST    (CPU_EXC_INTR_FIRST + 1)

static int test_intr_last = -1;
static int test_intr_status;
static struct semaphore test_intr_sems[2];

static void
test_intr_dummy_enable (void *arg __unused, uint32_t irq,
                        uint32_t cpu __unused)
{
  assert (irq >= TEST_INTR_FIRST && irq < TEST_INTR_LAST);
  test_intr_status = 1;
}

static void
test_intr_dummy_disable (void *arg __unused, uint32_t irq __unused)
{
  test_intr_status = 0;
}

static void
test_intr_dummy_eoi (void *arg __unused, uint32_t irq)
{
  test_intr_last = (int)irq;
}

static const struct intr_ops test_intr_ops =
{
  .enable = test_intr_dummy_enable,
  .disable = test_intr_dummy_disable,
  .eoi = test_intr_dummy_eoi
};

static void
test_intr (void *arg)
{
  struct cap_flow *flow = arg;

  struct
    {
      struct ipc_msg_data md;
      struct cap_kern_alert alert;
    } *data;

  int error = vm_map_anon_alloc ((void **)&data, vm_map_self (),
                                 sizeof (*data));
  assert (! error);

  // Test that the counter is preserved in presence of an error.
  error = cap_recv_alert (flow, 0, 1, 0);
  assert (error == EFAULT);

  error = cap_recv_alert (flow, &data->alert, sizeof (data->alert), &data->md);
  assert (! error);

  assert (data->alert.intr.irq == TEST_INTR_FIRST);
  assert (data->alert.intr.count == 2);
  assert (data->md.task_id == 0);
  assert (data->md.thread_id == 0);

  assert (test_intr_last == (int)data->alert.intr.irq);
  assert (test_intr_status == 1);

  semaphore_post (test_intr_sems + 0);
  semaphore_wait (test_intr_sems + 1);

  error = cap_recv_alert (flow, &data->alert, sizeof (data->alert), &data->md);
  assert (! error);

  assert (data->alert.intr.irq == TEST_INTR_FIRST);
  assert (data->alert.intr.count == 1);
  assert (data->md.task_id == 0);
  assert (data->md.thread_id == 0);
}

static void
test_fire_intr (int cnt, int intr)
{
  thread_intr_enter ();
  cpu_intr_disable ();
  for (int i = 0; i < cnt; ++i)
    intr_handle (intr);
  cpu_intr_enable ();
  thread_intr_leave ();
}

TEST_DEFERRED (intr)
{
  semaphore_init (test_intr_sems + 0, 0, 0xff);
  semaphore_init (test_intr_sems + 1, 0, 0xff);
  intr_register_ctl (&test_intr_ops, 0, TEST_INTR_FIRST, TEST_INTR_LAST);

  struct cap_flow *flow;
  int error = cap_flow_create (&flow, 0, 0, 0);
  assert (! error);

  error = cap_intr_register (flow, TEST_INTR_FIRST);
  assert (! error);

  test_fire_intr (2, TEST_INTR_FIRST);

  struct thread *thr;
  error = test_util_create_thr (&thr, test_intr, flow, "intr");
  assert (! error);

  semaphore_wait (test_intr_sems + 0);
  test_fire_intr (1, TEST_INTR_FIRST);
  semaphore_post (test_intr_sems + 1);

  thread_join (thr);
  error = cap_intr_unregister (flow, TEST_INTR_FIRST);
  assert (! error);
  return (TEST_OK);
}
