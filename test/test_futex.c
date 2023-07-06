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
 * This module aims to test the full futex API. It is composed of 4
 * sub-tests, each one dedicated to testing particular features:
 *
 *  - The first sub-test checks the basic futex API: waiting, waiting
 *    and requeuing using regular futexes (local, non-robust, non-PI).
 *
 *  - The second sub-test checks that shared futexes work correctly. It
 *    creates a second task and a thread in it. This new thread will map
 *    memory from the same object as the initial thread. This way, the
 *    shared memory mapping can be used to place a futex there and check
 *    that it works correctly.
 *
 *  - The third sub-test checks that PI futexes allow waiting threads to
 *    propagate their priorities to lower-priority threads. The initial
 *    thread creates a futex, acquires it by writing its TID to it and
 *    then creates 2 real-time threads that will wait on the futex. The
 *    first thread then checks that it has inherited their priority and
 *    is running boosted.
 *
 *  - The fourth sub-test checks that robust futexes are handled correctly
 *    when a thread exits while holding one or more of them. It creates the
 *    linked list of futexes (plus its 'pending' one), sets the futex word
 *    to its TID and the FUTEX_WAITERS bit and then exits without unlocking
 *    them. Another thread waits for it to exit and then waits on the futexes,
 *    checking that the FUTEX_OWNER_DIED bit has been set.
 */

#include <stdio.h>

#include <kern/futex.h>
#include <kern/task.h>
#include <kern/user.h>

#include <test/test.h>

#include <vm/map.h>
#include <vm/object.h>

struct test_futex_obj
{
  struct futex_robust_list head;
  uint64_t prev;   // Unused.
};

struct test_futex_data
{
  struct thread *thr;
  struct futex_td td;
  struct test_futex_obj objs[3];
};

static void
test_futex_helper (void *arg)
{
  int error = futex_wait (arg, 0, 0, 0);
  assert (! error);
}

static void
test_futex_shared_helper (void *arg)
{
  struct vm_map_entry *entry = arg;
  uintptr_t start = PAGE_SIZE * 100;
  int flags = VM_MAP_FLAGS (VM_PROT_RDWR, VM_PROT_RDWR, VM_INHERIT_SHARE,
                            VM_ADV_DEFAULT, 0);
  int error = vm_map_enter (vm_map_self (), &start, PAGE_SIZE, 0,
                            flags, entry->object, entry->offset);
  assert (! error);

  void *addr = (void *)start;
  error = futex_wait (addr, 0, FUTEX_SHARED, 0);
  assert (! error);
}

static void
test_futex_local (void *arg __unused)
{
  void *addr;
  int error = vm_map_anon_alloc (&addr, vm_map_self (), 1);
  assert (! error);

  // Don't touch the address' contents so we may test page faults here.
  error = futex_wait (addr, 1, 0, 0);
  assert (error == EAGAIN);

  error = futex_wait (addr, 0, FUTEX_TIMED, 10);
  assert (error == ETIMEDOUT);

  struct thread *thread;
  struct thread_attr attr;

  thread_attr_init (&attr, "futex/1");
  thread_create (&thread, &attr, test_futex_helper, addr);

  test_thread_wait_state (thread, THREAD_SLEEPING);

  futex_wake (addr, FUTEX_MUTATE, 1);
  assert (*(int *)addr == 1);
  thread_join (thread);
  *(int *)addr = 0;

  struct thread *thrs[4];
  for (size_t i = 0; i < ARRAY_SIZE (thrs); ++i)
    {
      char name[16];
      sprintf (name, "futex-L/%d", (int)(i + 1));

      thread_attr_init (&attr, name);
      error = thread_create (&thrs[i], &attr, test_futex_helper,
                             (int *)addr + (i & 1));
      assert (! error);

      test_thread_wait_state (thrs[i], THREAD_SLEEPING);
    }

  error = futex_requeue (addr, (int *)addr + 1, 0, FUTEX_BROADCAST);
  assert (! error);
  *(int *)addr = 1;
  error = futex_wake (addr, FUTEX_BROADCAST, 1);
  assert (! error);

  for (size_t i = 0; i < ARRAY_SIZE (thrs); ++i)
    thread_join (thrs[i]);

  *(int *)addr = 0;
  for (size_t i = 0; i < ARRAY_SIZE (thrs); ++i)
    {
      char name[16];
      sprintf (name, "futex-M/%d", (int)(i + 1));

      thread_attr_init (&attr, name);
      thread_create (&thrs[i], &attr, test_futex_helper,
                     (int *)addr + (i & 1));

      test_thread_wait_state (thrs[i], THREAD_SLEEPING);
    }

  *(int *)addr = 1;
  error = futex_requeue (addr, (int *)addr + 1, 1, 0);
  assert (! error);
  error = futex_wake (addr, FUTEX_BROADCAST, 0);
  assert (! error);

  // Wake the remaining thread.
  error = futex_wake ((int *)addr + 1, 0, 0);
  assert (! error);

  for (size_t i = 0; i < ARRAY_SIZE (thrs); ++i)
    thread_join (thrs[i]);
}

static void
test_futex_shared (void *arg __unused)
{
  void *addr;
  int error = vm_map_anon_alloc (&addr, vm_map_self (), 1);
  assert (! error);

  struct vm_map_entry entry;
  error = vm_map_lookup (vm_map_self (), (uintptr_t)addr, &entry);
  assert (! error);

  struct thread *thr;
  error = test_util_create_thr (&thr, test_futex_shared_helper,
                                &entry, "futex-sh-fork");

  test_thread_wait_state (thr, THREAD_SLEEPING);
  error = futex_wake (addr, FUTEX_MUTATE | FUTEX_SHARED, 1);
  thread_join (thr);
  vm_map_entry_put (&entry);
}

static void
test_futex_pi_helper (void *arg)
{
  int *futex = arg;
  int error = futex_wait (futex, (*futex & FUTEX_TID_MASK), FUTEX_PI, 0);
  if (! error)
    assert ((*futex & FUTEX_TID_MASK) == (uint32_t)thread_id (thread_self ()));
  else
    assert (error == EAGAIN);
}

static void
test_futex_pi (void *arg __unused)
{
  void *addr;
  int error = vm_map_anon_alloc (&addr, vm_map_self (), 1);
  assert (! error);

  int *futex = addr;
  *futex = thread_id (thread_self ());

  struct thread *thrs[2];
  struct thread_attr attr;

  thread_attr_init (&attr, "futex-pi/1");
  thread_attr_set_policy (&attr, THREAD_SCHED_POLICY_FIFO);
  thread_attr_set_priority (&attr, THREAD_SCHED_RT_PRIO_MAX / 2);
  error = thread_create (&thrs[0], &attr, test_futex_pi_helper, futex);
  assert (! error);

  thread_attr_init (&attr, "futex-pi/2");
  thread_attr_set_policy (&attr, THREAD_SCHED_POLICY_FIFO);
  thread_attr_set_priority (&attr, THREAD_SCHED_RT_PRIO_MAX / 2);
  error = thread_create (&thrs[1], &attr, test_futex_pi_helper, futex);
  assert (! error);

  test_thread_wait_state (thrs[0], THREAD_SLEEPING);
  test_thread_wait_state (thrs[1], THREAD_SLEEPING);

  assert (thread_real_sched_policy (thread_self ()) ==
          THREAD_SCHED_POLICY_FIFO);

  *futex = 0;
  error = futex_wake (futex, FUTEX_PI | FUTEX_BROADCAST, 0);
  assert (! error);

  thread_join (thrs[0]);
  thread_join (thrs[1]);
}

static void
test_futex_robust_helper (void *arg)
{
  struct test_futex_data *data = arg;
  struct futex_td *td = &data->td;
  int val = thread_id (thread_self ()) | FUTEX_WAITERS;

  for (size_t i = 0; i < ARRAY_SIZE (data->objs); ++i)
    data->objs[i].head.futex = val;

  td->pending = &data->objs[0].head;
  data->objs[1].head.next = (uint64_t)(uintptr_t)&data->objs[2].head;
  data->objs[2].head.next = 0;
  td->list = &data->objs[1].head;

  test_thread_wait_state (data->thr, THREAD_SLEEPING);
  futex_td_exit (td);
}

static void
test_futex_robust (void *arg __unused)
{
  void *addr;
  int error = vm_map_anon_alloc (&addr, vm_map_self (), 1);
  assert (! error);

  struct test_futex_data *data = addr;
  data->thr = thread_self ();

  struct thread *thr;
  struct thread_attr attr;

  thread_attr_init (&attr, "futex-robust/1");
  error = thread_create (&thr, &attr, test_futex_robust_helper, addr);
  assert (! error);

  error = futex_wait (&data->objs[2].head.futex, FUTEX_WAITERS |
                      thread_id (thread_self ()), 0, 0);
  assert (!error || error == EAGAIN);

  thread_join (thr);
  for (size_t i = 0; i < ARRAY_SIZE (data->objs); ++i)
    assert ((data->objs[i].head.futex & FUTEX_OWNER_DIED) != 0);
}

TEST_DEFERRED (futex)
{
  struct thread *thread;
  int error;

  error = test_util_create_thr (&thread, test_futex_local, NULL, "futex");
  assert (! error);
  thread_join (thread);
  error = test_util_create_thr (&thread, test_futex_shared, NULL, "futex-sh");
  assert (! error);
  thread_join (thread);

  error = test_util_create_thr (&thread, test_futex_pi, NULL, "futex-pi");
  assert (! error);
  thread_join (thread);

  error = test_util_create_thr (&thread, test_futex_robust,
                                NULL, "futex-robust");
  assert (! error);
  thread_join (thread);

  return (TEST_OK);
}
