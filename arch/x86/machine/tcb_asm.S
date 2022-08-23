/*
 * Copyright (c) 2012-2017 Richard Braun.
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

#include <kern/init.h>
#include <machine/asm.h>
#include <machine/cpu.h>

.section INIT_SECTION

#ifdef __LP64__

ASM_ENTRY (tcb_context_load)
.cfi_startproc
  movq (%rdi), %rbp          // load frame pointer from TCB.
  movq 8(%rdi), %rsp         // load stack pointer from TCB.
  jmp tcb_context_restore
.cfi_endproc
ASM_END (tcb_context_load)

#else

ASM_ENTRY (tcb_context_load)
.cfi_startproc
  movl 4(%esp), %eax         // load TCB address.
  movl (%eax), %ebp          // load frame pointer from TCB.
  movl 4(%eax), %esp         // load stack pointer from TCB.
  jmp tcb_context_restore
.cfi_endproc
ASM_END (tcb_context_load)

#endif

.text

#ifdef __LP64__

ASM_ENTRY (tcb_start)
.cfi_startproc
.cfi_undefined 16
  popq %rdi              // load function.
  popq %rsi              // load argument.

  /*
   * Use the call instruction to start a clean stack trace.
   *
   * Note that, on amd64, the stack must be 16-byte before the call
   * instruction, so that "$(rsp + 8)" is always a multiple
   * of 16 when control is transferred to the function entry point,
   * which is another reason to use call instead of a bare jump.
   */
  call thread_main

  // Never reached.
  nop                    /* make the return address point to an instruction
                          * inside the function to have a clean stack trace. */
.cfi_endproc
ASM_END (tcb_start)

ASM_ENTRY (tcb_context_switch)
.cfi_startproc
  pushq %rbx             // store registers as required by ABI.
  pushq %r12
  pushq %r13
  pushq %r14
  pushq %r15
.cfi_offset 3, -16
.cfi_offset 12, -24
.cfi_offset 13, -32
.cfi_offset 14, -40
.cfi_offset 15, -48
.cfi_def_cfa 7, 48

  movq %rbp, (%rdi)      // store frame pointer into prev TCB.
  movq %rsp, 8(%rdi)     // store stack pointer into prev TCB.
  movq (%rsi), %rbp      // load frame pointer from next TCB.
  movq 8(%rsi), %rsp     // load stack pointer from next TCB.

.global tcb_context_restore
tcb_context_restore:
  popq %r15              // load registers as required by ABI.
  popq %r14
  popq %r13
  popq %r12
  popq %rbx
.cfi_def_cfa 7, 8
  ret
.cfi_endproc
ASM_END (tcb_context_switch)

#else

ASM_ENTRY (tcb_start)
.cfi_startproc
.cfi_undefined 8
  call thread_main       /* the stack already contains the expected arguments
                          * in the expected order, use the call instruction to
                          * start a clean stack trace. */

  // Never reached.
  nop                    /* make the return address point to an instruction
                          * inside the function to have a clean stack trace. */
.cfi_endproc
ASM_END (tcb_start)

ASM_ENTRY (tcb_context_switch)
.cfi_startproc
  movl 4(%esp), %eax     // load prev TCB address.
  movl 8(%esp), %ecx     // load next TCB address.

  pushl %ebx             // store registers as required by ABI.
  pushl %edi
  pushl %esi
.cfi_offset 3, -8
.cfi_offset 7, -12
.cfi_offset 6, -16
.cfi_def_cfa 4, 16

  movl %ebp, (%eax)      // store frame pointer into prev TCB.
  movl %esp, 4(%eax)     // store stack pointer into prev TCB.
  movl (%ecx), %ebp      // load frame pointer from next TCB.
  movl 4(%ecx), %esp     // load stack pointer from next TCB.

/*
 * This code is run on context restoration. The frame and stack pointers
 * have already been loaded to their correct values. Load registers which
 * were stored on the stack when the context was saved and return.
 */
.global tcb_context_restore
tcb_context_restore:
  popl %esi
  popl %edi
  popl %ebx
.cfi_def_cfa 4, 4
  ret
.cfi_endproc
ASM_END (tcb_context_switch)

#endif
