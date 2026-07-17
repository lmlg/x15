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
 */

#include <errno.h>
#include <string.h>
#include <syscall.h>

#include <kern/atomic.h>
#include <kern/init.h>
#include <kern/kmem.h>
#include <kern/log.h>
#include <kern/signal.h>
#include <kern/syscall_i.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/user.h>
#include <kern/uthread.h>

#include <machine/cpu.h>
#include <machine/signal.h>
#include <machine/pmap.h>

#include <vm/map.h>
#include <vm/page.h>

/*
 * Default signal actions.
 *
 * Default action for most signals is to terminate the process.
 * Some signals are ignored by default (e.g. SIGCHLD, SIGWINCH).
 */
enum
{
  SIGNAL_DEFAULT_TERM,
  SIGNAL_DEFAULT_IGN,
  SIGNAL_DEFAULT_STOP,
};

static const uint8_t signal_default_actions[NSIG] =
{
  [0] = SIGNAL_DEFAULT_IGN,
  [SIGHUP]     = SIGNAL_DEFAULT_TERM,
  [SIGINT]     = SIGNAL_DEFAULT_TERM,
  [SIGQUIT]    = SIGNAL_DEFAULT_TERM,
  [SIGILL]     = SIGNAL_DEFAULT_TERM,
  [SIGTRAP]    = SIGNAL_DEFAULT_TERM,
  [SIGABRT]    = SIGNAL_DEFAULT_TERM,
  [SIGBUS]     = SIGNAL_DEFAULT_TERM,
  [SIGFPE]     = SIGNAL_DEFAULT_TERM,
  [SIGKILL]    = SIGNAL_DEFAULT_TERM,
  [SIGUSR1]    = SIGNAL_DEFAULT_TERM,
  [SIGSEGV]    = SIGNAL_DEFAULT_TERM,
  [SIGUSR2]    = SIGNAL_DEFAULT_TERM,
  [SIGPIPE]    = SIGNAL_DEFAULT_TERM,
  [SIGALRM]    = SIGNAL_DEFAULT_TERM,
  [SIGTERM]    = SIGNAL_DEFAULT_TERM,
  [SIGSTKFLT]  = SIGNAL_DEFAULT_TERM,
  [SIGCHLD]    = SIGNAL_DEFAULT_IGN,
  [SIGCONT]    = SIGNAL_DEFAULT_IGN,
  [SIGSTOP]    = SIGNAL_DEFAULT_STOP,
  [SIGTSTP]    = SIGNAL_DEFAULT_STOP,
  [SIGTTIN]    = SIGNAL_DEFAULT_STOP,
  [SIGTTOU]    = SIGNAL_DEFAULT_STOP,
  [SIGURG]     = SIGNAL_DEFAULT_IGN,
  [SIGXCPU]    = SIGNAL_DEFAULT_TERM,
  [SIGXFSZ]    = SIGNAL_DEFAULT_TERM,
  [SIGVTALRM]  = SIGNAL_DEFAULT_TERM,
  [SIGPROF]    = SIGNAL_DEFAULT_TERM,
  [SIGWINCH]   = SIGNAL_DEFAULT_IGN,
  [SIGIO]      = SIGNAL_DEFAULT_TERM,
  [SIGPWR]     = SIGNAL_DEFAULT_IGN,
  [SIGSYS]     = SIGNAL_DEFAULT_TERM,
};

static struct vm_page *signal_trampoline_page;

void
signal_task_init (struct task *task)
{
  for (int i = 0; i < NSIG; i++)
    {
      task->sig_actions[i].sa_size = sizeof (task->sig_actions[i]);
      task->sig_actions[i].sa_flags = 0;
      task->sig_actions[i].sa_handler = SIG_DFL;
    }
}

// Find the first pending, unblocked signal.
static int
signal_pick (struct uthread *uthr)
{
  sigset_t deliverable = uthr->sig_pending & ~uthr->sig_mask;

  // SIGKILL and SIGSTOP have priority regardless of their signal number.
  if (deliverable & SIG_BIT (SIGKILL))
    return (SIGKILL);
  else if (deliverable & SIG_BIT (SIGSTOP))
    return (SIGSTOP);

  for (int i = 1; i < NSIG; i++)
    if (deliverable & SIG_BIT (i))
      return (i);

  return (0);
}

static void
signal_suspend_all (struct task *task, struct thread *self)
{
  if (atomic_swap (&task->suspending, 1, ATOMIC_ACQUIRE) != 0)
    return;

  ADAPTIVE_LOCK_GUARD (&task->lock);
  struct thread *thread;
  list_for_each_entry (&task->threads, thread, task_node)
    if (thread != self)
      thread_suspend (thread);
}

static void
signal_terminate_all (struct task *task, int signo)
{
  if (atomic_swap (&task->terminate, signo, ATOMIC_ACQ_REL) == 0)
    thread_terminate_all (task);

  thread_exit ();
}

void
signal_check (struct cpu_exc_frame *frame, struct thread *self)
{
  struct uthread *uthr = self->uthread;
  if (!uthr)
    return;

  /*
   * If the task has been marked for termination (another thread
   * received a default-terminate signal), exit immediately.
   */
  _Auto task = self->task;
  if (task->terminate)
    thread_exit ();

  int signo = signal_pick (uthr);
  if (!signo)
    return;

  // Clear the pending bit — the signal is being delivered.
  uthr->sig_pending &= ~SIG_BIT (signo);

  _Auto act = &self->task->sig_actions[signo];
  void (*handler) (int) = act->sa_handler;

  if (handler == SIG_IGN)
    return;
  else if (handler == SIG_DFL)
    {
      int action = signal_default_actions[signo];

      if (action == SIGNAL_DEFAULT_IGN)
        return;
      else if (action == SIGNAL_DEFAULT_STOP)
        signal_suspend_all (task, self);
      else if (action == SIGNAL_DEFAULT_TERM)
        signal_terminate_all (task, signo);
      else
        panic ("invalid default action: %d", action);
    }
  else if (signal_set_trampoline (frame, uthr, signo, (uintptr_t)handler) < 0)
    /*
     * Failed to save the signal trampoline on the user stack.
     * The stack is unusable — terminate the task immediately
     * rather than letting the thread continue with a broken
     * state.
     */
    signal_terminate_all (task, SIGSEGV);
}

void
signal_restore (struct cpu_exc_frame *frame, struct thread *self)
{
  struct uthread *uthr = self->uthread;
  if (!uthr)
    return;

  // Read the saved frame from the user stack.
  if (user_copy_from (frame, (void *)uthr->sig_saved_sp,
                      sizeof (*frame)) != 0)
    {
      /*
       * Failed to read the saved frame from the user stack.
       * The frame still contains the trampoline context, so
       * returning would re-enter the trampoline and loop
       * forever calling sigreturn. Terminate the task to
       * break the cycle.
       */
      if (atomic_swap (&self->task->terminate, SIGSEGV,
                       ATOMIC_ACQ_REL) == 0)
        thread_terminate_all (self->task);
      thread_exit ();
    }

  // Restore the signal mask.
  uthr->sig_mask = uthr->sig_saved_mask;
}

/*
 * Map the trampoline page into a task's address space.
 *
 * Called during task creation to ensure the trampoline is available
 * in every user task.
 */
int
signal_map_trampoline (struct task *task)
{
  if (!signal_trampoline_page || task->map == vm_map_get_kernel_map ())
    return (0);

  int flags = VM_MAP_FLAGS (VM_PROT_READ | VM_PROT_EXEC,
                            VM_PROT_READ | VM_PROT_EXEC,
                            VM_INHERIT_NONE, VM_ADV_DEFAULT,
                            VM_MAP_FIXED | VM_MAP_PHYS);
  uintptr_t addr = SIGNAL_TRAMPOLINE_ADDR;
  return (vm_map_enter (task->map, &addr, PAGE_SIZE, flags, 0,
                        vm_page_to_pa (signal_trampoline_page)));
}

static int __init
signal_setup (void)
{
  // Allocate the trampoline page and write the trampoline code.
  signal_trampoline_page = vm_page_alloc (0, VM_PAGE_SEL_DIRECTMAP,
                                          VM_PAGE_KERNEL, 0);
  if (!signal_trampoline_page)
    panic ("signal: unable to allocate trampoline page");

  vm_page_init_refcount (signal_trampoline_page);

  signal_init_trampoline (vm_page_direct_ptr (signal_trampoline_page));
  log_info ("signal: trampoline mapped at %p",
            (void *)SIGNAL_TRAMPOLINE_ADDR);
  return (0);
}

INIT_OP_DEFINE (signal_setup,
                INIT_OP_DEP (kmem_setup, true),
                INIT_OP_DEP (vm_map_setup, true),
                INIT_OP_DEP (log_setup, true));

// Signal syscall implementations.

SYSCALL (sigaction, int signo, const struct sigaction *new,
         struct sigaction *old)
{
  if (!signal_valid (signo))
    return (-EINVAL);

  _Auto task = task_self ();
  if (old && user_write_struct (old, &task->sig_actions[signo],
                                sizeof (*old)) != 0)
    return (-EFAULT);

  if (new)
    {
      if (!signal_catchable (signo))
        return (-EPERM);

      struct sigaction sa;
      if (user_read_struct (&sa, new, sizeof (sa)) != 0)
        return (-EFAULT);

      task->sig_actions[signo] = sa;
    }

  return (0);
}

SYSCALL (sigprocmask, int how, const sigset_t *new, sigset_t *old)
{
  _Auto uthr = thread_self()->uthread;

  if (!uthr)
    return (-EINVAL);
  else if (old && user_copy_to (old, &uthr->sig_mask, sizeof (*old)) != 0)
    return (-EFAULT);
  else if (new)
    {
      sigset_t nset;
      if (user_copy_from (&nset, new, sizeof (nset)) != 0)
        return (-EFAULT);

      // SIGKILL and SIGSTOP cannot be blocked.
      nset &= ~(SIG_BIT (SIGKILL) | SIG_BIT (SIGSTOP));

      switch (how)
        {
          case SIG_BLOCK:
            uthr->sig_mask |= nset;
            break;
          case SIG_UNBLOCK:
            uthr->sig_mask &= ~nset;
            break;
          case SIG_SETMASK:
            uthr->sig_mask = nset;
            break;
          default:
            return (-EINVAL);
        }
    }

  return (0);
}

SYSCALL (kill, int tid, int signo)
{
  if (!signal_valid (signo))
    return (-EINVAL);

  _Auto target = thread_by_kuid ((uint32_t)tid);
  if (!target)
    return (-ESRCH);

  int error = thread_send_signal (target, signo);
  thread_unref (target);
  return (-error);
}
