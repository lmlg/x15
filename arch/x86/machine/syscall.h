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

#ifndef X86_MACHINE_SYSCALL_H
#define X86_MACHINE_SYSCALL_H

#include <stdint.h>
#include <stdnoreturn.h>

struct cpu_exc_frame;

void syscall_arch_init (void);

/*
 * Architecture-specific implementation of transition from
 * kernel space to user space.
 */
noreturn void syscall_jump_to_user (uintptr_t pc, uintptr_t sp);

/*
 * Low-level assembly routine that performs the actual privilege
 * transition. Called by syscall_arch_jump_to_user after TSS setup.
 */
noreturn void syscall_jump_to_user_asm (uintptr_t pc, uintptr_t sp);

// Low-level assembly entry point.
void syscall_entry (void);

// Low-level assembly trampoline.
void syscall_handler (struct cpu_exc_frame *frame);

// Perform a syscall from userspace (must be a macro).

#ifdef __LP64__
#  define SYSCALL_ARCH_IMPL(sysno, a1, a2, a3, a4, a5, a6)   \
     ({   \
        long ret_;   \
        register uintptr_t r8_ asm ("r8") = (a5);   \
        register uintptr_t r9_ asm ("r9") = (a6);   \
        register uintptr_t r10_ asm ("r10") = (a4);   \
        asm volatile ("syscall" : "=a" (ret_) :   \
                      "a" (sysno), "D" (a1), "S" (a2), "d" (a3),   \
                      "r" (r8_), "r" (r9_), "r" (r10_) :   \
                      "rcx", "r11", "memory");   \
        ret_;   \
      })
#else

#  define SYSCALL_ARCH_IMPL(sysno, a1, a2, a3, a4, a5, a6)   \
     ({   \
        long ret_;   \
        uintptr_t regs_[] = { (a1), (a6) };   \
        asm volatile   \
          (   \
            "pushl %1\n\t"   \
            "pushl %%ebx\n\t"   \
            "pushl %%ebp\n\t"   \
            "movl 8(%%esp), %%ebx\n\t"   \
            "movl 4(%%ebx), %%ebp\n\t"   \
            "movl (%%ebx), %%ebx\n\t"   \
            "int $128\n\t"   \
            "popl %%ebp\n\t"   \
            "popl %%ebx\n\t"   \
            "addl $4, %%esp\n\t"   \
            : "=a" (ret_)   \
            : "g" (&regs_), "a" (sysno), "c" (a2), "d" (a3),   \
              "S" (a4), "D" (a5)   \
            : "memory"   \
          );   \
        ret_;   \
      })

#endif

#endif /* X86_MACHINE_SYSCALL_H */
