/*
 * Copyright (c) 2026 Agustina Arzille.
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
 * This module tests signal delivery entirely from userspace. The test
 * contains a single function that is used both as the entry into userspace as
 * well as the signal handler. The user thread data has some flags that are
 * used to distinguish between both "modes".
 *
 * The test itself will perform the following actions:
 * - Fetch the task and thread ids. The thread id will be used to send a
 *   signal later on.
 * - The syscall 'sigaction' will be used to establish a signal handler and
 *   fetch the previous one. It will thus test that the default action was
 *   installed for the test signal.
 * - The test signal will be blocked with the syscall 'sigprocmask' and the
 *   previous mask will be fetched and verified.
 * - One of the flags in the user data will be flipped and then the signal
 *   will be unmasked, thus leading to the delivery of the signal.
 * - The entry point will be entered in signal handler mode, and the flags
 *   will be verified for correctness.
 * - After the handler runs, control goes back to the entry point for some
 *   more verification.
 */

#include <signal.h>
#include <syscall.h>

#include <kern/signal.h>
#include <kern/syscall.h>

#include <machine/syscall.h>

#include <test/test.h>

#define TEST_SIGNAL   SIGIO

struct test_signal_args
{
  volatile int inside;
  volatile int flag;
  uintptr_t pc;
};

static void
test_signal_prepare (uintptr_t pc, void *arg)
{
  ((struct test_signal_args *)arg)->pc = pc;
}

static void __attribute__ ((aligned (PAGE_SIZE)))
test_signal_uentry (int sig)
{
  struct test_signal_args *args = test_uthread_arg ();
  if (!args->inside)
    {
      args->inside = 1;
      args->flag = 0;

      uint64_t tids;
      long err = SYSCALL_UENTER (SYS_gettids, &tids);
      if (err != 0 || !tids)
        test_uthread_err (err, 0);

      { // Install the handler.
        struct sigaction old, new;
        new.sa_size = sizeof (new);
        new.sa_flags = 0;
        new.sa_handler = (typeof (new.sa_handler))args->pc;
        old.sa_size = sizeof (old);

        err = SYSCALL_UENTER (SYS_sigaction, TEST_SIGNAL, &new, &old);
        if (err != 0)
          test_uthread_err (err, 0);
        else if (old.sa_handler != SIG_DFL)
          test_uthread_err (old.sa_handler, 0);
      }

      { // Block the signal.
        sigset_t old, new = SIG_BIT (TEST_SIGNAL);
        err = SYSCALL_UENTER (SYS_sigprocmask, SIG_BLOCK, &new, &old);

        if (err != 0)
          test_uthread_err (err, 0);
        else if (old & SIG_BIT (TEST_SIGNAL))
          test_uthread_err (0, 0);
      }

      err = SYSCALL_UENTER (SYS_kill, (uint32_t)tids, TEST_SIGNAL);
      if (err != 0)
        test_uthread_err (err, 0);

      // Make sure the signal is blocked here.
      args->flag = 1;

      sigset_t set = SIG_BIT (TEST_SIGNAL);
      SYSCALL_UENTER (SYS_sigprocmask, SIG_UNBLOCK, &set);
      asm volatile ("" : : : "memory");

      if (args->flag)
        test_uthread_err (args->flag, 0);

      SYSCALL_UENTER (SYS_thread_exit, 0);
      __builtin_unreachable ();
    }
  else if (sig != TEST_SIGNAL)
    test_uthread_err (sig, TEST_SIGNAL);

  if (!args->flag)
    test_uthread_err (args->flag, 0);

  args->flag = 0;
}

TEST_DEFERRED (signal)
{
  struct test_utask utask;
  int err = test_util_create_utask (&utask, "signal-uspace");
  test_assert_zero (err);

  void *data = test_util_utask_reserve (&utask, sizeof (uintptr_t));
  test_assert_nonnull (data);

  struct test_uthread_attr attr;
  attr.fnsize = PAGE_SIZE;
  attr.task = &utask;
  attr.prepare = test_signal_prepare;

  struct test_uthread uthr;
  err = test_util_create_uthr (&uthr, &attr,
                               (uintptr_t)test_signal_uentry, data);
  test_assert_zero (err);
  test_util_uthr_join (&uthr);

  return (TEST_OK);
}
