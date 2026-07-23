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
 *   installed for the test signal. The handler will also be set for the
 *   signal SIGSEGV.
 * - The test signal will be blocked with the syscall 'sigprocmask' and the
 *   previous mask will be fetched and verified.
 * - One of the flags in the user data will be flipped and then the signal
 *   will be unmasked, thus leading to the delivery of the signal.
 * - The entry point will be entered in signal handler mode, and the flags
 *   will be verified for correctness.
 * - After the handler runs, control goes back to the entry point for some
 *   more verification. Afterwards, a segmentation fault will be generated.
 * - For the second time, the signal handler will be run, this time to
 *   verify that the contents of the 'siginfo_t' are correct.
 */

#include <signal.h>
#include <syscall.h>

#include <kern/signal.h>
#include <kern/syscall.h>
#include <kern/task.h>

#include <test/test.h>

#define TEST_SIGNAL   SIGIO

struct test_signal_args
{
  volatile int inside;
  volatile int flag;
  volatile int segfault;
  int *addr;
  uintptr_t pc;
};

static void
test_signal_prepare (uintptr_t pc, void *arg)
{
  struct test_signal_args *ptr = arg;
  ptr->pc = pc;
  ptr->addr = (void *)(pc + 800 * PAGE_SIZE);
}

#if defined (__LP64__) && defined (__x86_64__)
#  define CTX_PC(ctx)   (((ucontext_t *)ctx)->uc_mcontext.regs[17])
#endif

static void __attribute__ ((aligned (PAGE_SIZE)))
test_signal_uentry (int sig, siginfo_t *sinfo, void *ctx __unused)
{
  struct test_signal_args *args = test_uthread_arg ();
  if (!args->inside)
    { // We enter here when the user thread starts.
      args->inside = 1;
      args->flag = 0;
      args->segfault = 0;

      uint64_t tids;
      long err = SYSCALL_UENTER (SYS_gettids, &tids);
      if (err != 0 || !tids)
        test_uthread_err (err, 0);

      { // Install the handler.
        struct sigaction old, new;
        new.sa_size = sizeof (new);
        new.sa_flags = SA_SIGINFO;
        new.sa_mask = 0;
        new.sa_sigaction = (typeof (new.sa_sigaction))args->pc;
        old.sa_size = sizeof (old);

        err = SYSCALL_UENTER (SYS_sigaction, TEST_SIGNAL, &new, &old);
        test_uassert_eq (err, 0);
        test_uassert_eq (old.sa_handler, SIG_DFL);

        err = SYSCALL_UENTER (SYS_sigaction, SIGSEGV, &new, 0);
        test_uassert_eq (err, 0);
      }

      { // Block the signal.
        sigset_t old, new = SIG_BIT (TEST_SIGNAL);
        err = SYSCALL_UENTER (SYS_sigprocmask, SIG_BLOCK, &new, &old);

        test_uassert_eq (err, 0);
        test_uassert_eq (old & SIG_BIT (TEST_SIGNAL), 0);
      }

      // Send the signal.
      {
        siginfo_t sin = { .si_signo = TEST_SIGNAL, .si_code = -1 };
        err = SYSCALL_UENTER (SYS_tkill, SIG_SEND_SELF, -1, 0, &sin);
        test_uassert_eq (err, 0);
      }

      // Make sure the signal is blocked here.
      args->flag = 1;

      sigset_t set = SIG_BIT (TEST_SIGNAL);
      err = SYSCALL_UENTER (SYS_sigprocmask, SIG_UNBLOCK, &set);

      test_uassert_eq (err, 0);
      test_uassert_eq (args->flag, 0);

      args->segfault = 1;
      asm volatile ("" : : : "memory");
      *args->addr = 1;
    }
  else
    { // This is the branch when we receive a signal.
      if (args->segfault)
        {
          test_uassert_eq (sinfo->si_addr, args->addr);
          test_uassert_eq (sinfo->si_code, SEGV_MAPERR);
          test_uassert_eq (sinfo->si_pid, 0);
#ifdef CTX_PC
          test_uassert_ge (CTX_PC (ctx), args->pc);
          test_uassert_le (CTX_PC (ctx), args->pc + PAGE_SIZE);
#endif
          test_uthread_exit ();
        }

      test_uassert_eq (sig, TEST_SIGNAL);
      test_uassert_ne (args->flag, 0);
      test_uassert_gt (sinfo->si_pid, 0);
      args->flag = 0;
    }
}

#undef CTX_PC

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
  err = test_util_uthr_join (&uthr);
  test_assert_zero (err);

  return (TEST_OK);
}
