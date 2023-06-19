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
#include <kern/task.h>

#include <vm/map.h>

#include <test/test.h>

#define TEST_INTR_FIRST   CPU_EXC_INTR_FIRST
#define TEST_INTR_LAST    (CPU_EXC_INTR_FIRST + 1)

static int test_intr_last = -1;

static void
test_intr_dummy_enable (void *arg __unused, uint32_t irq,
                        uint32_t cpu __unused)
{
  assert (irq >= TEST_INTR_FIRST && irq < TEST_INTR_LAST);
}

static void
test_intr_dummy_disable (void *arg __unused, uint32_t irq __unused)
{
}

static void
test_intr_dummy_eoi (void *arg __unused, uint32_t irq)
{
  assert (test_intr_last < 0);
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
  int capx = cap_intern (flow, 0);
  assert (capx >= 0);

  struct ipc_msg_data *md;
  int error = vm_map_anon_alloc ((void **)&md, vm_map_self (), sizeof (*md));
  assert (! error);

  uint32_t irq;
  rcvid_t rcvid = cap_recv_bytes (capx, &irq, sizeof (irq), md);

  assert (rcvid == 0);
  assert (md->flags & IPC_MSG_INTR);
  assert (irq == TEST_INTR_FIRST);

  assert (cap_intr_eoi (flow, irq) == 0);
  assert (test_intr_last == (int)irq);
}

TEST_DEFERRED (intr)
{
  intr_register_ctl (&test_intr_ops, 0, TEST_INTR_FIRST, TEST_INTR_LAST);

  struct cap_flow *flow;
  int error = cap_flow_create (&flow, 0, 0);
  assert (! error);

  error = cap_intr_register (flow, TEST_INTR_FIRST);
  assert (! error);

  thread_intr_enter ();
  cpu_intr_disable ();
  intr_handle (TEST_INTR_FIRST);
  cpu_intr_enable ();
  thread_intr_leave ();

  struct thread *thr;
  error = test_util_create_thr (&thr, test_intr, flow, "intr");
  assert (! error);

  thread_join (thr);
  error = cap_intr_unregister (flow, TEST_INTR_FIRST);
  assert (! error);
  return (TEST_OK);
}
