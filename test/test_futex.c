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
 * This module aims to test the full futex API. It is composed of the
 * following sub-tests, each one dedicated to testing particular features:
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
 *
 *  - The fifth sub-test creates a userspace thread and performs several
 *    futex-related syscalls. It does not perform the whole test suite again;
 *    it simply tests that entry and exit are performed correctly, as well as
 *    making sure that arguments are checked correctly.
 */

#include <stdio.h>
#include <syscall.h>

#include <kern/futex.h>
#include <kern/task.h>
#include <kern/user.h>

#include <machine/syscall.h>

#include <test/test.h>

#include <vm/map.h>
#include <vm/object.h>

struct test_futex_robust_data
{
  struct futex_robust_list l1;
  struct futex_robust_list l2;
  struct thread *thr;
};

struct test_futex_uargs
{
  int futex1;
};

static void
test_futex_helper (void *arg)
{
  int error = futex_wait (arg, 0, 0, 0);
  test_assert_or (error == 0, error == EAGAIN);
}

static void
test_futex_local (void *arg __unused)
{
  void *addr;
  int error = vm_map_anon_alloc (&addr, vm_map_self (), 1);
  test_assert_zero (error);

  // Don't touch the address' contents so we may test page faults here.
  error = futex_wait (addr, 1, 0, 0);
  test_assert_eq (error, EAGAIN);

  error = futex_wait (addr, 0, FUTEX_FLG_TIMED, 10);
  test_assert_eq (error, ETIMEDOUT);

  struct thread *thread;
  struct thread_attr attr;

  thread_attr_init (&attr, "futex/1");
  thread_create (&thread, &attr, test_futex_helper, addr);

  test_thread_wait_state (thread, THREAD_SLEEPING);

  futex_wake (addr, FUTEX_FLG_MUTATE, 1);
  test_assert_eq (*(int *)addr, 1);
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
      test_assert_eq (error, 0);

      test_thread_wait_state (thrs[i], THREAD_SLEEPING);
    }

  error = futex_requeue (addr, (int *)addr + 1, 0, FUTEX_FLG_BROADCAST);
  test_assert_zero (error);
  *(int *)addr = 1;
  error = futex_wake (addr, FUTEX_FLG_BROADCAST, 1);
  test_assert_zero (error);

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
  test_assert_zero (error);
  error = futex_wake (addr, FUTEX_FLG_BROADCAST, 0);
  test_assert_zero (error);

  // Wake the remaining thread.
  error = futex_wake ((int *)addr + 1, 0, 0);
  test_assert_zero (error);

  for (size_t i = 0; i < ARRAY_SIZE (thrs); ++i)
    thread_join (thrs[i]);
}

static void
test_futex_shared_helper (void *arg)
{
  struct vm_map_entry *entry = arg;
  uintptr_t start = PAGE_SIZE * 100;
  int flags = VM_MAP_FLAGS (VM_PROT_RDWR, VM_PROT_RDWR, VM_INHERIT_SHARE,
                            VM_ADV_DEFAULT, 0);
  int error = vm_map_enter (vm_map_self (), &start, PAGE_SIZE,
                            flags, entry->object, entry->offset);
  test_assert_zero (error);

  void *addr = (void *)start;
  error = futex_wait (addr, 0, FUTEX_FLG_SHARED, 0);
  test_assert_or (error == 0, error == EAGAIN);
  test_assert_eq (*(int *)addr, 1);
}

static void
test_futex_shared (void *arg __unused)
{
  void *addr;
  int error = vm_map_anon_alloc (&addr, vm_map_self (), 1);
  test_assert_zero (error);

  _Auto entry = vm_map_find (vm_map_self (), (uintptr_t)addr);
  test_assert_nonnull (entry);

  struct thread *thr;
  error = test_util_create_thr (&thr, test_futex_shared_helper,
                                entry, "futex-sh-fork");

  test_thread_wait_state (thr, THREAD_SLEEPING);
  error = futex_wake (addr, FUTEX_FLG_MUTATE | FUTEX_FLG_SHARED, 1);
  test_assert_zero (error);
  thread_join (thr);
  vm_map_entry_put (entry);
}

static void
test_futex_pi_helper (void *arg)
{
  int *futex = arg;
  int error = futex_wait (futex, (*futex & FUTEX_TID_MASK), FUTEX_FLG_PI, 0);
  if (! error)
    test_assert_eq ((*futex & FUTEX_TID_MASK),
                    (uint32_t)thread_id (thread_self ()));
  else
    test_assert_eq (error, EAGAIN);
}

static bool
test_futex_pi_wait_sched (void)
{
  for (int i = 0; i < 1000; ++i)
    if (thread_real_sched_policy (thread_self ()) == THREAD_SCHED_POLICY_FIFO)
      return (true);
    else
      thread_yield ();

  return (false);
}

static void
test_futex_pi (void *arg __unused)
{
  void *addr;
  int error = vm_map_anon_alloc (&addr, vm_map_self (), 1);
  test_assert_zero (error);

  int *futex = addr;
  *futex = thread_id (thread_self ());

  struct thread *thrs[2];
  struct thread_attr attr;

  thread_attr_init (&attr, "futex-pi/1");
  thread_attr_set_policy (&attr, THREAD_SCHED_POLICY_FIFO);
  thread_attr_set_priority (&attr, THREAD_SCHED_RT_PRIO_MAX / 2);
  error = thread_create (&thrs[0], &attr, test_futex_pi_helper, futex);
  test_assert_eq (error, 0);

  thread_attr_init (&attr, "futex-pi/2");
  thread_attr_set_policy (&attr, THREAD_SCHED_POLICY_FIFO);
  thread_attr_set_priority (&attr, THREAD_SCHED_RT_PRIO_MAX / 2);
  error = thread_create (&thrs[1], &attr, test_futex_pi_helper, futex);
  test_assert_zero (error);

  test_thread_wait_state (thrs[0], THREAD_SLEEPING);
  test_thread_wait_state (thrs[1], THREAD_SLEEPING);

  test_assert_eq (test_futex_pi_wait_sched (), true);
  error = futex_wake (futex, FUTEX_FLG_PI | FUTEX_FLG_BROADCAST |
                             FUTEX_FLG_MUTATE, 0);
  test_assert_zero (error);

  thread_join (thrs[0]);
  thread_join (thrs[1]);
}

static void
test_futex_robust_helper (void *arg)
{
  struct test_futex_robust_data *data = arg;
  _Auto uthr = uthread_allocate ();
  test_assert_nonnull (uthr);
  thread_self()->uthread = uthr;

  int val = thread_id (thread_self ()) | FUTEX_WAITERS;
  data->l1.futex = data->l2.futex = val;
  uthr->futex_td.pending = &data->l1;
  data->l2.next = ~(uint64_t)0;   // Invalid address.
  uthr->futex_td.list = &data->l2;

  test_thread_wait_state (data->thr, THREAD_SLEEPING);
}

static void
test_futex_robust (void *arg __unused)
{
  void *addr;
  int error = vm_map_anon_alloc (&addr, vm_map_self (), 1);
  test_assert_zero (error);

  struct test_futex_robust_data *data = addr;
  data->thr = thread_self ();

  struct thread *thr;
  struct thread_attr attr;

  thread_attr_init (&attr, "futex-robust/1");
  error = thread_create (&thr, &attr, test_futex_robust_helper, addr);
  test_assert_zero (error);

  error = futex_wait (&data->l2.futex, FUTEX_WAITERS | thread_id (thr), 0, 0);
  test_assert_or (error == 0, error == EAGAIN);

  thread_join (thr);
  test_assert_ne ((data->l1.futex & FUTEX_OWNER_DIED), 0);
  test_assert_ne ((data->l2.futex & FUTEX_OWNER_DIED), 0);
}

static void
test_futex_uentry (void)
{
  struct test_futex_uargs *args = test_uthread_arg ();
  long error = SYSCALL_UENTER (SYS_futex, &args->futex1, FUTEX_OP_WAIT, 1);

  if (error != -EAGAIN)
    test_uthread_err (error, -EAGAIN);

  uint64_t ticks = 10;
  error = SYSCALL_UENTER (SYS_futex, &args->futex1,
                          FUTEX_OP_WAIT | FUTEX_FLG_TIMED, 0, &ticks);
  if (error != -ETIMEDOUT)
    test_uthread_err (error, -ETIMEDOUT);

  error = SYSCALL_UENTER (SYS_futex, ~0ul & ~(sizeof (int) - 1),
                          FUTEX_OP_WAIT, 0);
  if (error != -EFAULT)
    test_uthread_err (error, -EFAULT);

  error = SYSCALL_UENTER (SYS_futex, 0, ~0ul, 0);
  if (error != -ENOSYS)
    test_uthread_err (error, -ENOSYS);

  SYSCALL_UENTER (SYS_thread_exit, 0);
  __builtin_unreachable ();
}

TEST_UTHREAD_DECL_FNSIZE (test_futex_uentry);

static void
test_ufutex (void)
{
  struct test_utask utask;
  int err = test_util_create_utask (&utask, "futex-uspace");
  test_assert_zero (err);

  void *data = test_util_utask_reserve (&utask,
                                        sizeof (struct test_futex_uargs));
  test_assert_nonnull (data);

  struct test_uthread_attr attr;
  attr.fnsize = TEST_UTHREAD_FNSIZE (test_futex_uentry);
  attr.task = &utask;

  struct test_uthread uthr;
  err = test_util_create_uthr (&uthr, &attr,
                               (uintptr_t)test_futex_uentry, data);
  test_assert_zero (err);
  test_util_uthr_join (&uthr);
}

TEST_DEFERRED (futex)
{
  struct thread *thread;
  int error;

  error = test_util_create_thr (&thread, test_futex_local, NULL, "futex");
  test_assert_zero (error);
  thread_join (thread);

  error = test_util_create_thr (&thread, test_futex_shared, NULL, "futex-sh");
  test_assert_zero (error);
  thread_join (thread);

  error = test_util_create_thr (&thread, test_futex_pi, NULL, "futex-pi");
  test_assert_zero (error);
  thread_join (thread);

  error = test_util_create_thr (&thread, test_futex_robust,
                                NULL, "futex-robust");
  test_assert_zero (error);
  thread_join (thread);

  test_ufutex ();

  return (TEST_OK);
}
