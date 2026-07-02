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

#ifndef KERN_SYSCALL_H
#define KERN_SYSCALL_H

#include <stdint.h>
#include <stdnoreturn.h>

#include <kern/init.h>
#include <kern/types.h>

struct cpu_exc_frame;

/*
 * System call handler function type.
 *
 * Every syscall handler has this uniform signature regardless of how many
 * arguments it actually uses. Unused arguments are simply ignored by the
 * handler. The return value is 0 or a positive integer on success, or a
 * negative errno on error.
 */
typedef ssize_t (*syscall_fn_t) (uintptr_t, uintptr_t, uintptr_t,
                                 uintptr_t, uintptr_t, uintptr_t);

// Initialize the system call subsystem.
int syscall_setup (void);

/*
 * Dispatch a system call.
 *
 * Arguments:
 *  nr   - System call number (from RAX/EAX).
 *  args - Array of up to 6 arguments extracted from the exception frame
 *         in the architecture-specific calling convention.
 *
 * Returns 0 or a positive value on success, or a negative errno on error.
 */
ssize_t syscall_dispatch (uintptr_t nr, const uintptr_t args[6]);

// Generic callback on transition to kernel space via a system call.
void syscall_enter (struct cpu_exc_frame *frame);

// Generic callback on transition to kernel space via an interrupt or exception.
void syscall_interrupt_enter (struct cpu_exc_frame *frame);


#endif /* KERN_SYSCALL_H */
