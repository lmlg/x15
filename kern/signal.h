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
 * POSIX signals.
 */

#ifndef KERN_SIGNAL_H
#define KERN_SIGNAL_H

#include <stdbool.h>
#include <signal.h>

#include <kern/init.h>
#include <kern/syscall_i.h>

struct cpu_exc_frame;
struct task;
struct thread;
struct uthread;

// Check whether the given signal number is valid.
static inline bool
signal_valid (int signo)
{
  return (signo > 0 && signo < NSIG);
}

/*
 * Check whether a signal can be caught or blocked.
 *
 * SIGKILL and SIGSTOP cannot be caught, blocked, or ignored.
 */
static inline bool
signal_catchable (int signo)
{
  return (signo != SIGKILL && signo != SIGSTOP);
}

// Initialize the signal actions for a task.
void signal_task_init (struct task *task);

/*
 * Check for pending unblocked signals and deliver the first one.
 *
 * If a signal is deliverable, the exception frame is modified in-place
 * to invoke the handler. The original context is saved on the user stack.
 *
 */
void signal_check (struct cpu_exc_frame *frame, struct thread *self);

// Find the first pending signal that matches a wait set.
int signal_select (struct uthread *uthr, sigset_t wset);

// Deliver a synchronous signal.
void signal_sync_deliver (struct cpu_exc_frame *frame, struct thread *self,
                          siginfo_t *sinfo);

/*
 * Restore the saved context from a previous signal delivery.
 *
 * Called from the sigreturn system call. Reads the saved context
 * from the user stack and restores it into the given frame, so that
 * the assembly return path resumes the interrupted user code.
 */
void signal_restore (struct cpu_exc_frame *frame, struct thread *self);

/*
 * Map the signal trampoline page into a task's address space.
 *
 * Called during task creation to ensure the trampoline is available
 * in every user task. Skips the kernel task.
 */
int signal_map_trampoline (struct task *task);

// Allocate a pending 'siginfo_t'.
int signal_alloc_siginfo (struct thread *self, siginfo_t *sinfo);

// Pop a queued siginfo_t for the given signal, or NULL if none.
siginfo_t* signal_pop_siginfo (struct uthread *uthr, int signo);

// Deallocate signal-related objects from a user thread.
void signal_uthr_dealloc (struct uthread *uthread);

// Syscall entry points for signal management.
SYSCALL_DECL (sigaction);
SYSCALL_DECL (sigprocmask);
SYSCALL_DECL (tkill);
SYSCALL_DECL (sigtimedwait);

/*
 * This init operation provides :
 *  - signal trampoline page
 *  - module fully initialized
 */
INIT_OP_DECLARE (signal_setup);

#endif
