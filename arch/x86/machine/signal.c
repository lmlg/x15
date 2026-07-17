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

#include <signal.h>
#include <stdint.h>
#include <syscall.h>

#include <kern/signal.h>
#include <kern/user.h>

#include <machine/cpu.h>
#include <machine/signal.h>

int
signal_set_trampoline (struct cpu_exc_frame *frame, struct uthread *uthr,
                       int signo, uintptr_t handler)
{
  /*
   * Deliver the signal to the handler.
   *
   * The user stack is arranged as follows (high to low):
   *
   *   [old user RSP]
   *   ... (alignment)
   *   [saved cpu_exc_frame]    <- uthr->sig_saved_sp
   *   [trampoline address]     <- new user RSP
   *
   * When the handler returns (via ret), it jumps to the trampoline,
   * which performs the sigreturn syscall to restore the saved frame.
   */
  uintptr_t old_rsp = frame->words[CPU_EXC_FRAME_RSP];
  size_t frame_size = sizeof (*frame);

  // Align the saved frame start down to 16 bytes.
  uintptr_t saved_sp = (old_rsp - frame_size) & ~(uintptr_t)0xf;

  // Save enough for the trampoline return address.
  uintptr_t new_rsp = saved_sp - sizeof (uintptr_t);

  // Write the saved frame to the user stack.
  if (user_copy_to ((void *)saved_sp, frame, frame_size) != 0)
    return (-1);

  // Write the trampoline return address.
  uintptr_t tramp = SIGNAL_TRAMPOLINE_ADDR;
  if (user_copy_to ((void *)new_rsp, &tramp, sizeof (tramp)) != 0)
    return (-1);

  // Save the current mask and auto-block the signal during the handler.
  uthr->sig_saved_mask = uthr->sig_mask;
  uthr->sig_mask |= SIG_BIT (signo);
  uthr->sig_saved_sp = saved_sp;

  // Modify the frame to invoke the handler.
  frame->words[CPU_EXC_FRAME_RSP] = new_rsp;
  frame->words[CPU_EXC_FRAME_RIP] = (uintptr_t)handler;
  frame->words[CPU_EXC_FRAME_RDI] = (uintptr_t)signo;
  frame->words[CPU_EXC_FRAME_RFLAGS] = CPU_EFL_IF | CPU_EFL_ONE;

  // Clear argument registers to avoid leaking kernel data.
  frame->words[CPU_EXC_FRAME_RSI] = 0;
  frame->words[CPU_EXC_FRAME_RDX] = 0;
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
