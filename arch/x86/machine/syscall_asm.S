/*
 * Copyright (c) 2026 Agustina Arzille
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

#include <machine/asm.h>
#include <machine/cpu.h>

#define CPU_SEL_USER(sel)   ((sel) | CPU_PL_USER)

#ifdef __LP64__

.text

ASM_ENTRY (syscall_entry)
.cfi_startproc
  // Swap GS base to access kernel per-CPU variables.
  swapgs

  // Save user RSP to our per-CPU scratchpad.
  movq %rsp, %gs:syscall_user_rsp

  // Load kernel stack pointer (tss.rsp0)
  movq %gs:(cpu_desc + CPU_TSS_RSP0_OFFSET), %rsp

  // Build the cpu_exc_frame on the kernel stack
  pushq $CPU_SEL_USER(CPU_GDT_SEL_USER_DATA)   // SS (0x2B)
  pushq %gs:syscall_user_rsp                   // RS
  pushq %r11                                   // RFLAGS
  pushq $CPU_SEL_USER(CPU_GDT_SEL_USER_CODE)   // CS (0x33)
  pushq %rcx                                   // RIP

  pushq $0                                     // error code
  pushq $0                                     // vector number

  /*
   * Push general purpose registers in the correct order to match cpu_exc_frame:
   * Order: R15, R14, R13, R12, R11, R10, R9, R8, RDI, RSI, RBP, RDX, RCX, RBX, RAX
   */
  pushq %r15
  pushq %r14
  pushq %r13
  pushq %r12
  pushq %r11
  pushq %r10
  pushq %r9
  pushq %r8
  pushq %rdi
  pushq %rsi
  pushq %rbp
  pushq %rdx
  pushq %rcx
  pushq %rbx
  pushq %rax

  // Pass pointer to frame as the first argument (RDI)
  movq %rsp, %rdi
  call syscall_handler

  // Check scheduling before returning
  call thread_schedule

  // Restore registers from the frame
  popq %rax
  popq %rbx
  popq %rcx
  popq %rdx
  popq %rbp
  popq %rsi
  popq %rdi
  popq %r8
  popq %r9
  popq %r10
  popq %r11
  popq %r12
  popq %r13
  popq %r14
  popq %r15

  // Pop vector and error
  addq $16, %rsp

  // Now pop the remaining standard exception/sysret elements
  popq %rcx       // RIP
  addq $8, %rsp   // skip CS
  popq %r11       // RFLAGS
  popq %rsp       // RSP (switches back to user stack)

  // Swap GS base back to userspace.
  swapgs
  sysretq
.cfi_endproc
ASM_END (syscall_entry)

#else

.text

ASM_ENTRY (syscall_entry)
.cfi_startproc
  /*
   * The CPU has already switched to the kernel stack and pushed:
   * SS, ESP, EFLAGS, CS, EIP.
  */
  pushl $0     // error code (index 12)
  pushl $128   // vector 0x80 (index 11)

  cpu_ll_exc_store_registers     // pushes GS, FS, ES, DS, EDI, ESI, EBP, EDX, ECX, EBX, EAX

  // Set kernel data segment register so that the kernel can safely execute.
  movl $CPU_GDT_SEL_DATA, %eax
  movl %eax, %ds
  movl %eax, %es

  // Pass ESP (pointer to frame) to the C handler.
  pushl %esp
  call syscall_handler
  addl $4, %esp

  call thread_schedule
  cpu_ll_exc_load_registers

  iretl
.cfi_endproc
ASM_END (syscall_entry)

#endif

/*
 * syscall_jump_to_user_asm
 *
 * Perform the actual privilege transition from kernel mode to user mode.
 *
 * x86-64: uses the sysretq instruction.
 *   sysretq loads RIP from RCX, RFLAGS from R11, and derives
 *   CS/SS from the STAR MSR.
 *
 * i386: uses the iretl instruction.
 *   An IRET frame is built on the kernel stack containing the
 *   user segment selectors (with RPL=3), the user EIP, ESP, and
 *   EFLAGS (with interrupts enabled).
 *
 * Arguments (x86-64): RDI = pc, RSI = sp
 * Arguments (i386):  4(%esp) = pc, 8(%esp) = sp
 *
 * This function never returns.
 */

#ifdef __LP64__

ASM_ENTRY (syscall_jump_to_user_asm)
.cfi_startproc
  // Disable interrupts before the transition
  cli

  /*
   * Set up registers for sysretq:
   *   RCX = user RIP (loaded by sysretq into RIP)
   *   R11 = user RFLAGS (loaded by sysretq into RFLAGS)
   *   RSP = user stack pointer
   */
  movq %rdi, %rcx
  movq %rsi, %rsp
  movq $(CPU_EFL_IF | CPU_EFL_ONE), %r11

  // Swap GS base to userspace.
  swapgs

  sysretq
.cfi_endproc
ASM_END (syscall_jump_to_user_asm)

#else

ASM_ENTRY (syscall_jump_to_user_asm)
.cfi_startproc
  // Disable interrupts before the transition
  cli

  /*
   * Read arguments from the stack before we build the IRET frame.
   * Stack layout at entry:
   *   4(%esp) = pc    (user instruction pointer)
   *   8(%esp) = sp    (user stack pointer)
   */
  movl 4(%esp), %ecx   // ECX = user EIP
  movl 8(%esp), %edx   // EDX = user ESP

  /*
   * Build the IRET frame on the kernel stack.
   * IRET expects (from top to bottom):
   *   EIP, CS, EFLAGS, ESP, SS
   */
  pushl $CPU_SEL_USER(CPU_GDT_SEL_USER_DATA)   // SS (user data, RPL=3)
  pushl %edx                                   // ESP (user stack)
  pushl $(CPU_EFL_IF | CPU_EFL_ONE)            // EFLAGS (IF and reserved bit)
  pushl $CPU_SEL_USER(CPU_GDT_SEL_USER_CODE)   // CS (user code, RPL=3)
  pushl %ecx                                   // EIP (user entry point)

  /*
   * Load user data segment into DS and ES.
   * FS and GS are left unchanged (used for per-CPU data / TLS);
   * user code can reconfigure them via syscalls if needed.
   */
  movl $CPU_SEL_USER(CPU_GDT_SEL_USER_DATA), %eax
  movl %eax, %ds
  movl %eax, %es

  iretl
.cfi_endproc
ASM_END (syscall_jump_to_user_asm)

#endif

.section .note.GNU-stack,"",@progbits
