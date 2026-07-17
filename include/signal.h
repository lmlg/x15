/*
 * Copyright (c) 2026
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

#ifndef SIGNAL_H
#define SIGNAL_H

#include <stdint.h>

/*
 * Signal numbers.
 *
 * Only classic (non-real-time) signals are supported for now.
 * New entries must preserve existing numbering.
 */

#define SIGHUP       1
#define SIGINT       2
#define SIGQUIT      3
#define SIGILL       4
#define SIGTRAP      5
#define SIGABRT      6
#define SIGBUS       7
#define SIGFPE       8
#define SIGKILL      9
#define SIGUSR1     10
#define SIGSEGV     11
#define SIGUSR2     12
#define SIGPIPE     13
#define SIGALRM     14
#define SIGTERM     15
#define SIGSTKFLT   16
#define SIGCHLD     17
#define SIGCONT     18
#define SIGSTOP     19
#define SIGTSTP     20
#define SIGTTIN     21
#define SIGTTOU     22
#define SIGURG      23
#define SIGXCPU     24
#define SIGXFSZ     25
#define SIGVTALRM   26
#define SIGPROF     27
#define SIGWINCH    28
#define SIGIO       29
#define SIGPWR      30
#define SIGSYS      31

/*
 * Number of supported signals.
 *
 * Classic signals use the range [1, NSIG-1]. Index 0 is unused
 * (reserved as the "no signal" sentinel).
 */
#define NSIG   32

// Signal set type (bitmap).
typedef uint64_t sigset_t;

// Generate a mask for a single signal.
#define SIG_BIT(signo)   (1ULL << ((signo) - 1))

// Mask covering all classic signals.
#define SIG_MASK_ALL   ((1ULL << (NSIG - 1)) - 1)

// Special handler dispositions.
#define SIG_DFL   ((void (*)(int))0)
#define SIG_IGN   ((void (*)(int))1)
#define SIG_ERR   ((void (*)(int))-1)

// sigaction flags.
#define SA_RESTART   0x01

// sigprocmask "how" values.
#define SIG_BLOCK     0
#define SIG_UNBLOCK   1
#define SIG_SETMASK   2

/*
 * Signal action structure.
 *
 * For now, only the old-style handler is supported (single argument,
 * no siginfo_t or ucontext_t).
 */
struct sigaction
{
  uint32_t sa_size;
  uint32_t sa_flags;
  void (*sa_handler)(int);
};

/*
 * Virtual address of the signal trampoline page.
 *
 * The kernel maps a single page containing the trampoline code into
 * every user task at this address. The trampoline performs the
 * sigreturn system call when the signal handler returns.
 */
#define SIGNAL_TRAMPOLINE_ADDR   0x7fffefffe000UL

// Siginfo codes.

// For SIGSEGV
#define SEGV_MAPERR   1   // Address not mapped to object.
#define SEGV_ACCERR   2   // Invalid permissions.

#endif
