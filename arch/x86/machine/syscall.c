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
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <kern/init.h>
#include <kern/log.h>
#include <kern/percpu.h>
#include <kern/syscall.h>
#include <kern/thread.h>
#include <machine/cpu.h>
#include <machine/syscall.h>

#ifdef __LP64__
/*
 * Scratchpad per-CPU variable to store the userspace stack pointer
 * during the syscall entry sequence (before switching to the kernel stack).
 */
uintptr_t syscall_user_rsp __percpu;

// Ensure the offset of tss.rsp0 in struct cpu matches CPU_TSS_RSP0_OFFSET.
static_assert (offsetof (struct cpu, tss.rsp0) == CPU_TSS_RSP0_OFFSET,
               "CPU_TSS_RSP0_OFFSET mismatch");
#endif

//  High-level system call C handlers.
#ifdef __LP64__

void
syscall_handler (struct cpu_exc_frame *frame)
{
  syscall_enter (frame);

  uintptr_t args[6], nr = frame->words[CPU_EXC_FRAME_RAX];
  args[0] = frame->words[CPU_EXC_FRAME_RDI];
  args[1] = frame->words[CPU_EXC_FRAME_RSI];
  args[2] = frame->words[CPU_EXC_FRAME_RDX];
  args[3] = frame->words[CPU_EXC_FRAME_R10];
  args[4] = frame->words[CPU_EXC_FRAME_R8];
  args[5] = frame->words[CPU_EXC_FRAME_R9];
  frame->words[CPU_EXC_FRAME_RAX] = syscall_dispatch (nr, args);
}

#else

void
syscall_handler (struct cpu_exc_frame *frame)
{
  syscall_enter (frame);

  uintptr_t args[6], nr = frame->words[CPU_EXC_FRAME_EAX];
  args[0] = frame->words[CPU_EXC_FRAME_EBX];
  args[1] = frame->words[CPU_EXC_FRAME_ECX];
  args[2] = frame->words[CPU_EXC_FRAME_EDX];
  args[3] = frame->words[CPU_EXC_FRAME_ESI];
  args[4] = frame->words[CPU_EXC_FRAME_EDI];
  args[5] = frame->words[CPU_EXC_FRAME_EBP];
  frame->words[CPU_EXC_FRAME_EAX] = syscall_dispatch (nr, args);
}

#endif

// Per-CPU configuration for system calls.

/*
 * C wrapper for the kernel-to-userspace transition.
 *
 * Before performing the actual transition, we must save the current kernel
 * stack pointer into the TSS so that future interrupts and syscalls from
 * user mode know where to switch to.
 */
noreturn void
syscall_jump_to_user (uintptr_t pc, uintptr_t sp)
{
  cpu_set_kernel_stack ((uintptr_t)thread_self()->stack + TCB_STACK_SIZE);
  syscall_jump_to_user_asm (pc, sp);
}

static void __init
syscall_percpu_setup (void)
{
#ifdef __LP64__
  // Enable SCE (bit 0) and NXE (bit 11) in EFER.
  uint64_t efer = cpu_get_msr64 (CPU_MSR_EFER);
  cpu_set_msr64 (CPU_MSR_EFER, efer | CPU_EFER_SCE | CPU_EFER_NXE);

  /*
   * Configure the STAR MSR:
   *   STAR[47:32] = Kernel base selector (0x08)
   *   STAR[63:48] = User base selector (0x23) -> SS=40 (0x28), CS=48 (0x30)
   */
  uint32_t star_high = ((uint32_t)(CPU_GDT_SEL_USER_DATA - 8) | 3 ) << 16 |
                       (uint32_t)CPU_GDT_SEL_CODE;
  cpu_set_msr (0xc0000081, star_high, 0);

  // Configure LSTAR MSR with the 64-bit syscall assembly entry point.
  cpu_set_msr64 (0xc0000082, (uintptr_t)syscall_entry);

  // Configure SFMASK MSR to clear the Interrupt Flag (IF) during syscall.
  cpu_set_msr64 (0xc0000084, CPU_EFL_IF);
#else
  /*
   * Install the custom low-level trap/interrupt gate for 'int 0x80'
   * in the IDT with User privilege level (DPL=3).
   */
  cpu_idt_set_user_intr_gate (0x80, syscall_entry);
#endif
}

static struct percpu_op syscall_percpu_op =
  PERCPU_OP_INITIALIZER (syscall_percpu_setup);

void __init
syscall_arch_init (void)
{
  percpu_register_op (&syscall_percpu_op);
}
