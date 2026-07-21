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
 * Definitions for signals on x86.
 */

#ifndef X86_SIGNAL_H
#define X86_SIGNAL_H

#include <signal.h>

struct cpu_exc_frame;
struct uthread;
struct __siginfo;

// Set the signal trampoline on a CPU frame for a specific user thread.
int signal_set_trampoline (struct cpu_exc_frame *frame, struct uthread *uthr,
                           int signo, siginfo_t *sinfo, uintptr_t handler);

// Copy the contents of the signal trampoline into a buffer.
void signal_init_trampoline (void *page);

#endif
