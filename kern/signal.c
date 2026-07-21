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

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <syscall.h>

#include <kern/atomic.h>
#include <kern/capability.h>
#include <kern/cspace.h>
#include <kern/init.h>
#include <kern/kmem.h>
#include <kern/signal.h>
#include <kern/slist.h>
#include <kern/syscall_i.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/user.h>
#include <kern/uthread.h>

#include <machine/cpu.h>
#include <machine/signal.h>

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

int
signal_select (struct uthread *uthr, sigset_t wset)
{
  sigset_t deliverable = uthr->sig_pending & ~uthr->sig_mask & wset;

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

  adaptive_lock_acquire (&task->lock);
  struct thread *thread;
  list_for_each_entry (&task->threads, thread, task_node)
    if (thread != self)
      thread_suspend (thread);

  // Drop the lock before suspending ourselves.
  adaptive_lock_release (&task->lock);
  thread_suspend (self);
}

static _Noreturn void
signal_terminate_all (struct task *task, int signo)
{
  if (atomic_swap (&task->terminate, signo << 8, ATOMIC_ACQ_REL) == 0)
    thread_terminate_all (task);

  thread_exit ();
}

static siginfo_t*
signal_si_from_node (struct slist_node *node)
{
  return ((siginfo_t *)((char *)node - offsetof (siginfo_t, __si_link)));
}

siginfo_t*
signal_pop_siginfo (struct uthread *uthr, int signo)
{
  struct slist_node *prev = NULL;
  MUTEX_GUARD (&uthr->mutex);
  _Auto slist = &uthr->alloc_siginfo;

  slist_for_each (slist, snode)
    {
      _Auto entry = signal_si_from_node (snode);
      if (entry->si_signo == signo)
        {
          slist_remove (slist, prev);
          entry->__si_link = 0;   // Don't leak the kernel pointer.
          return (entry);
        }

      prev = snode;
    }

  return (NULL);
}

void
signal_uthr_dealloc (struct uthread *uthr)
{
  struct slist_node *snode, *ts;
  slist_for_each_safe (&uthr->alloc_siginfo, snode, ts)
    kmem_free (signal_si_from_node (snode), sizeof (siginfo_t));
}

void
signal_sync_deliver (struct cpu_exc_frame *frame, struct thread *self,
                     siginfo_t *sinfo)
{
  _Auto uthr = self->uthread;
  assert (uthr);

  int signo = sinfo->si_signo;
  _Auto task = self->task;

  if (task->terminate)
    thread_exit ();

  _Auto act = &task->sig_actions[signo];
  _Auto handler = act->sa_handler;

  /*
   * For signals like SIGSEGV or SIGILL, it's possible to set the
   * disposition to SIG_IGN. However, if they are generated *synchronously*,
   * they must be acted upon or else the process will be in an indetermined
   * state. For these signals, the default behaviour is to terminate the
   * process, so we always go for that.
   */

  if (handler == SIG_IGN || handler == SIG_DFL ||
      signal_set_trampoline (frame, uthr, signo,
                             sinfo, (uintptr_t)handler) < 0)
    signal_terminate_all (task, signo);
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

  int signo = signal_select (uthr, ~(sigset_t)0);
  if (!signo)
    return;

  // Clear the pending bit — the signal is being delivered.
  uthr->sig_pending &= ~SIG_BIT (signo);

  _Auto act = &task->sig_actions[signo];
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
      else
        signal_terminate_all (task, signo);
    }
  else
    {
      siginfo_t *sinfo = NULL;
      bool dealloc = true;

      if (act->sa_flags & SA_SIGINFO)
        {
          sinfo = signal_pop_siginfo (uthr, signo);
          if (! sinfo)
            {
              sinfo = alloca (sizeof (*sinfo));
              memset (sinfo, 0, sizeof (*sinfo));
              sinfo->si_signo = signo;
              dealloc = false;
            }
        }

      int err = signal_set_trampoline (frame, uthr, signo,
                                       sinfo, (uintptr_t)handler);
      if (sinfo && dealloc)
        kmem_free (sinfo, sizeof (*sinfo));

      if (err)
        /*
         * Failed to save the signal trampoline on the user stack.
         * The stack is unusable - terminate the task immediately
         * rather than letting the thread continue with a broken state.
         */
        signal_terminate_all (task, SIGSEGV);
    }
}

void
signal_restore (struct cpu_exc_frame *frame, struct thread *self)
{
  struct uthread *uthr = self->uthread;
  if (!uthr)
    return;

  struct unw_fixup fixup;
  int err = unw_fixup_save (&fixup);

  if (err)
    {
      /*
       * Failed to read the ucontext from the user stack.
       * The frame still contains the trampoline context, so returning would
       * re-enter the trampoline and loop forever calling sigreturn.
       * Terminate the task to break the cycle.
       */
    error:
      signal_terminate_all (self->task, SIGSEGV);
      return;
    }

  ucontext_t *uc = (void *)uthr->sig_saved_sp;
  if (!user_check_range (uc, sizeof (*uc)))
    goto error;

  // Restore the register state and signal mask.
  memcpy (frame->words, uc->uc_mcontext.regs, sizeof (uc->uc_mcontext.regs));
  uthr->sig_mask = uc->uc_sigmask;
  uthr->sig_saved_sp = 0;
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

int
signal_alloc_siginfo (struct thread *thread, siginfo_t *sinfo)
{
  siginfo_t *new;
  while (1)
    {
      new = kmem_alloc2 (sizeof (*new), KMEM_ALLOC_SLEEP);
      if (new)
        break;

      // We were probably interrupted by a signal. Yield to handle it.
      thread_yield ();
    }

  memcpy (new, sinfo, sizeof (*new));
  sinfo->__si_link = 0;
  MUTEX_GUARD (&thread->uthread->mutex);
  slist_insert_tail (&thread->uthread->alloc_siginfo,
                     (struct slist_node *)&new->__si_link);
  return (0);
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
  return (0);
}

INIT_OP_DEFINE (signal_setup,
                INIT_OP_DEP (kmem_setup, true),
                INIT_OP_DEP (vm_map_setup, true));

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

static int
signal_send_impl (struct thread *thread, siginfo_t *sinfo)
{
  int ret = signal_alloc_siginfo (thread, sinfo);
  if (ret == 0)
    ret = thread_send_signal (thread, sinfo->si_signo);

  return (ret);
}

static bool
signal_allowed (struct thread *thread, int signo)
{
  return ((thread->uthread->sig_mask & SIG_BIT (signo)) == 0);
}

static int
signal_send_in_task (struct thread *thread, siginfo_t *sinfo, bool unlock)
{
  thread_ref (thread);
  if (unlock)
    adaptive_lock_release (&thread->task->lock);

  int ret = signal_send_impl (thread, sinfo);
  thread->task->last_sig_thr = thread;
  thread_unref (thread);
  return (ret);
}

static int
signal_send_task (struct task *task, int tid, siginfo_t *sinfo)
{
  if (tid > 0)
    {
      _Auto thr = thread_by_kuid (tid);
      if (! thr)
        return (-ESRCH);
      else if (thr->task != task)
        {
          thread_unref (thr);
          return (-EPERM);
        }

      return (signal_send_in_task (thr, sinfo, false));
    }

  adaptive_lock_acquire (&task->lock);
  if (list_empty (&task->threads))
    {
      adaptive_lock_release (&task->lock);
      return (-ESRCH);
    }

  /*
   * Most tasks have a thread dedicated to signal handling, so we first
   * try to see if the signal is allowed on that thread.
   */

  if (task->last_sig_thr &&
      signal_allowed (task->last_sig_thr, sinfo->si_signo))
    return (signal_send_in_task (task->last_sig_thr, sinfo, true));

  // Find a thread that can accept the signal.
  struct thread *thread;
  list_for_each_entry (&task->threads, thread, task_node)
    if (signal_allowed (thread, sinfo->si_signo))
      return (signal_send_in_task (thread, sinfo, true));

  // All threads have the signal masked. Just send it to the first one.
  thread = list_first_entry (&task->threads, struct thread, task_node);
  return (signal_send_in_task (thread, sinfo, true));
}

SYSCALL (tkill, int how, int arg1, int arg2, siginfo_t *sinfo)
{
  siginfo_t tmp;
  if (user_copy_from (&tmp, sinfo, sizeof (tmp)) != 0)
    return (-EFAULT);
  else if (tmp.si_code >= 0)
    // Codes >= 0 are reserved for the kernel.
    return (-EPERM);
  else if (!signal_valid (tmp.si_signo))
    return (-EINVAL);

  _Auto self = thread_self ();
  _Auto caps = &self->task->caps;
  tmp.si_pid = task_id (self->task);

  switch (how)
    {
      case SIG_SEND_SELF:
        { // arg1 is the thread id or <= 0 for the current thread.
          struct thread *thread = self;
          bool unref = false;

          if (arg1 > 0 && thread_id (thread) != arg1)
            {
              _Auto tx = thread_by_kuid (arg1);
              if (! tx)
                return (-ESRCH);
              else if (thread->task != tx->task)
                return (-EPERM);

              unref = true;
              thread = tx;
            }

          int rv = signal_send_impl (thread, &tmp);
          if (unref)
            thread_unref (thread);

          return (rv);
        }

      case SIG_SEND_THREAD:
        { // arg1 is the capability. arg2 is ignored.
          _Auto cap = cspace_get (caps, arg1);
          if (! cap)
            return (-EINVAL);
          else if (cap_type (cap) != CAP_TYPE_THREAD)
            {
              cap_base_rel (cap);
              return (-EINVAL);
            }

          int rv = signal_send_impl (((struct cap_thread *)cap)->thread, &tmp);
          cap_base_rel (cap);
          return (rv);
        }

      case SIG_SEND_TASK:
        { // arg1 is the capability; arg2 is thread id (or -1 for any thread).
          _Auto cap = cspace_get (caps, arg1);
          if (! cap)
            return (-EINVAL);
          else if (cap_type (cap) != CAP_TYPE_TASK)
            {
              cap_base_rel (cap);
              return (-EINVAL);
            }

          int rv = signal_send_task (((struct cap_task *)cap)->task,
                                     arg2, &tmp);
          cap_base_rel (cap);
          return (rv);
        }

      default:
        return (-ENOSYS);
    }
}

SYSCALL (sigtimedwait, const sigset_t *set, siginfo_t *info,
         const uint64_t *timeout, const sigset_t *nsetp)
{
  if (!set)
    return (-EINVAL);

  struct unw_fixup fixup;
  int err = unw_fixup_save (&fixup);

  if (err)
    return (-err);
  else if (!user_check_range (set, sizeof (*set)) ||
           !user_check_range (info, sizeof (*info)) ||
           !user_check_range (timeout, sizeof (*timeout)) ||
           !user_check_range (nsetp, sizeof (*nsetp)))
    return (-EFAULT);

  sigset_t new_set, wait_set = *set;
  uint64_t ticks;

  if (timeout)
    {
      ticks = *timeout;
      timeout = &ticks;
    }

  if (nsetp)
    {
      new_set = *nsetp;
      nsetp = &new_set;
    }

  // SIGKILL and SIGSTOP cannot be waited for.
  wait_set &= ~(SIG_BIT (SIGKILL) | SIG_BIT (SIGSTOP));
  if (!wait_set)
    return (-EINVAL);

  siginfo_t si;
  int error = thread_sigwait (wait_set, &si, timeout, nsetp);
  if (error)
    return (-error);

  *info = si;
  return (si.si_signo);
}
