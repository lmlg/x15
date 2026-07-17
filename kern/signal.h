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
 * Called from the syscall and exception return paths, after
 * thread_schedule, before returning to user mode. If a signal is
 * deliverable, the exception frame is modified in-place to invoke
 * the handler. The original context is saved on the user stack.
 *
 * The frame argument points to the start of the cpu_exc_frame on
 * the kernel stack (the first saved register, e.g. RAX on x86-64).
 */
void signal_check (struct cpu_exc_frame *frame, struct thread *self);

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

// Syscall entry points for signal management.
SYSCALL_DECL (sigaction);
SYSCALL_DECL (sigprocmask);
SYSCALL_DECL (kill);

/*
 * This init operation provides :
 *  - signal trampoline page
 *  - module fully initialized
 */
INIT_OP_DECLARE (signal_setup);

#endif
