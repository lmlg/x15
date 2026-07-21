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
#define SA_RESTART     0x01
#define SA_SIGINFO     0x02
#define SA_RESETHAND   0x04
#define SA_ONSTACK     0x08
#define SA_NODEFER     0x10

// sigprocmask "how" values.
#define SIG_BLOCK     0
#define SIG_UNBLOCK   1
#define SIG_SETMASK   2

// tkill "how" values.
#define SIG_SEND_SELF     0
#define SIG_SEND_TASK     1
#define SIG_SEND_THREAD   2

union sigval
{
  int sival_int;
  void *sival_ptr;
};

typedef struct __siginfo
{
  int si_signo;
  int si_code;
  int si_errno;
  int si_pid;
  int si_uid;
  union
    {
      void *si_addr;
      union sigval si_value;
      struct
        {
          char __si_buf[40 - sizeof (long long)];
          long long __si_link __attribute__ ((aligned (8)));
        };
    };
} siginfo_t;

/*
 * Machine context.
 *
 * Contains the saved register state at the time the signal was
 * delivered. The layout matches the kernel's cpu_exc_frame, with
 * the same field indices (CPU_EXC_FRAME_RAX, etc). This structure
 * is architecture-specific — the array size differs between x86-64
 * (22 entries) and i386 (18 entries).
 */
#ifdef __LP64__
  #define MCONTEXT_NR_REGS   22
#else
  #define MCONTEXT_NR_REGS   18
#endif

typedef struct __mcontext
{
  uintptr_t regs[MCONTEXT_NR_REGS];
} mcontext_t;

/*
 * User context.
 *
 * Passed as the third argument to a signal handler installed with
 * SA_SIGINFO. The handler may modify uc_mcontext (e.g. to change
 * the return address) and uc_sigmask; these modifications take
 * effect when the handler returns via sigreturn.
 */
typedef struct __ucontext
{
  unsigned long uc_flags;
  struct __ucontext *uc_link;
  sigset_t uc_sigmask;
  mcontext_t uc_mcontext;
} ucontext_t;

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
  union
    {
      void (*sa_handler) (int);
      void (*sa_sigaction) (int, siginfo_t *, void *);
    };
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

// For SIGBUS
#define BUS_ADRALN   1   // Invalid address alignment.
#define BUS_ADRERR   2   // Nonexistent physical address.
#define BUS_OBJERR   3   // Object-specific hardware error.

// For SIGILL
#define ILL_ILLOPC   1   // Illegal opcode.
#define ILL_ILLOPN   2   // Illegal operand.
#define ILL_ILLADR   3   // Illegal addressing mode.
#define ILL_ILLTRP   4   // Illegal trap.
#define ILL_PRVOPC   5   // Privileged opcode.
#define ILL_PRVREG   6   // Privileged register.
#define ILL_COPROC   7   // Coprocessor error.

// For SIGFPE
#define FPE_INTDIV   1   // Integer divide by zero.
#define FPE_INTOVF   2   // Integer overflow.
#define FPE_FLTDIV   3   // Floating-point divide by zero.
#define FPE_FLTOVF   4   // Floating-point overflow.
#define FPE_FLTUND   5   // Floating-point underflow.
#define FPE_FLTRES   6   // Floating-point inexact result.
#define FPE_FLTINV   7   // Invalid floating-point operation.
#define FPE_FLTSUB   8   // Subscript out of range.

#endif
