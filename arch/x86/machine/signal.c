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

#include <stdint.h>
#include <string.h>
#include <syscall.h>

#include <kern/signal.h>
#include <kern/unwind.h>
#include <kern/user.h>

#include <machine/cpu.h>
#include <machine/signal.h>

int
signal_set_trampoline (struct cpu_exc_frame *frame, struct uthread *uthr,
                       int signo, const struct sigaction *act,
                       siginfo_t *sinfo, uintptr_t handler)
{
  /*
   * Deliver the signal to the handler.
   *
   * The user stack is arranged as follows (high to low):
   *
   *   [old user RSP or altstack top]
   *   ... (alignment)
   *   [ucontext_t]             <- ucontext_va (16-byte aligned)
   *       contains: uc_mcontext.regs[] = saved cpu_exc_frame
   *                 uc_sigmask = saved signal mask
   *   [padding if needed]
   *   [siginfo_t]              <- sinfo_va (16-byte aligned, if present)
   *   [trampoline address]     <- new user RSP (16k - 8 for ABI)
   *
   * When the handler returns (via ret), it pops the trampoline address from
   * RSP and jumps to it, which performs the sigreturn syscall to restore the
   * saved context from the ucontext_t.
   *
   * If SA_ONSTACK is set and an alternate signal stack is installed,
   * the handler runs on the alternate stack instead of the user's
   * current stack.
   *
   * Stack alignment: ucontext_va and sinfo_va are 16-byte aligned so
   * that new_rsp = sinfo_va - 8 (or ucontext_va - 8 if no siginfo)
   * is 16k - 8, satisfying the x86-64 ABI.
   */

  struct unw_fixup fixup;
  int err = unw_fixup_save (&fixup);

  if (err)
    return (-1);

  /*
   * Determine which stack to use. If SA_ONSTACK is set and an
   * alternate stack is enabled and not already in use, switch to it.
   */
  uintptr_t old_rsp = frame->words[CPU_EXC_FRAME_RSP];
  bool set_sa = false;

  if ((act->sa_flags & SA_ONSTACK) &&
      !(uthr->sigaltstack.ss_flags & SS_DISABLE) &&
      !(uthr->sigaltstack.ss_flags & SS_ONSTACK))
    { // Use the top of the alternate stack.
      old_rsp = (uintptr_t)uthr->sigaltstack.ss_sp + uthr->sigaltstack.ss_size;
      set_sa = true;
    }

  // Align the ucontext start down to 16 bytes.
  uintptr_t ucontext_va = (old_rsp - sizeof (ucontext_t)) & ~(uintptr_t)0xf;
  if (!user_check_range ((const void *)ucontext_va, sizeof (ucontext_t)))
    return (-1);

  { // Write the ucontext_t to the user stack.
    ucontext_t *uc = (void *)ucontext_va;
    uc->uc_flags = 0;
    uc->uc_link = 0;
    uc->uc_sigmask = uthr->sig_mask;
    memcpy (uc->uc_mcontext.regs, frame->words, sizeof (uc->uc_mcontext.regs));
  }

  /*
   * If siginfo is present, write it below the ucontext.
   * Align sinfo_va down to 16 bytes.
   */
  uintptr_t sinfo_va = 0;

  if (sinfo)
    {
      sinfo_va = (ucontext_va - sizeof (*sinfo)) & ~(uintptr_t)0xf;
      if (!user_check_range ((const void *)sinfo_va, sizeof (*sinfo)))
        return (-1);

      memcpy ((void *)sinfo_va, sinfo, sizeof (*sinfo));
    }

  /*
   * The trampoline return address goes at the bottom of the signal
   * frame. RSP at handler entry must be 16k - 8.
   */
  uintptr_t new_rsp = (sinfo ? sinfo_va : ucontext_va) - sizeof (uintptr_t);
  if (!user_check_range ((const void *)new_rsp, sizeof (uintptr_t)))
    return (-1);

  *(uintptr_t *)new_rsp = SIGNAL_TRAMPOLINE_ADDR;

  /*
   * Only now, after setting up the user stack are we allowed to modify
   * the uthread's members safely.
   */

  uthr->sig_mask = act->sa_mask;

  // Auto-block the signal during the handler, unless SA_NODEFER.
  if (!(act->sa_flags & SA_NODEFER))
    uthr->sig_mask |= SIG_BIT (signo);

  if (set_sa)
    {
      uthr->sigaltstack.ss_flags |= SS_ONSTACK;
      uthr->sig_saved_altstack_sp = frame->words[CPU_EXC_FRAME_RSP];
    }

  uthr->sig_saved_sp = ucontext_va;

  // Modify the frame to invoke the handler.
  frame->words[CPU_EXC_FRAME_RSP] = new_rsp;
  frame->words[CPU_EXC_FRAME_RIP] = (uintptr_t)handler;
  frame->words[CPU_EXC_FRAME_RDI] = (uintptr_t)signo;
  frame->words[CPU_EXC_FRAME_RSI] = sinfo_va;
  frame->words[CPU_EXC_FRAME_RDX] = ucontext_va;
  frame->words[CPU_EXC_FRAME_RFLAGS] = CPU_EFL_IF | CPU_EFL_ONE;

  // Clear remaining argument registers to avoid leaking kernel data.
  frame->words[CPU_EXC_FRAME_RCX] = 0;
  frame->words[CPU_EXC_FRAME_R8] = 0;
  frame->words[CPU_EXC_FRAME_R9] = 0;
  frame->words[CPU_EXC_FRAME_R10] = 0;
  frame->words[CPU_EXC_FRAME_R11] = 0;
  frame->words[CPU_EXC_FRAME_RAX] = 0;
  return (0);
}

/*
 * Trampoline code.
 *
 * This is written to a physical page that is mapped into every user
 * task at SIGNAL_TRAMPOLINE_ADDR. When a signal handler returns, it
 * returns to this trampoline, which performs the sigreturn syscall.
 *
 * On x86-64:
 *   mov $SYS_sigreturn, %rax    # 48 c7 c0 <4 bytes>
 *   xor %rdi, %rdi              # 48 31 ff
 *   syscall                     # 0f 05
 */
static const unsigned char signal_trampoline_code[] =
{
  0x48, 0xc7, 0xc0, 0x00, 0x00, 0x00, 0x00,   // mov $0, %rax (filled later).
  0x48, 0x31, 0xff,                           // xor %rdi, %rdi
  0x0f, 0x05,                                 // syscall
};

void
signal_init_trampoline (void *page)
{
  uint32_t sysno = SYS_sigreturn;
  memcpy (page, signal_trampoline_code, sizeof (signal_trampoline_code));
  memcpy ((char *)page + 3, &sysno, sizeof (sysno));
}
