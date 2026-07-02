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
 */

#ifndef SYSCALL_H
#define SYSCALL_H

/*
 * System call numbers.
 *
 * This header is shared between the kernel and userspace.
 * New syscalls must be appended at the end to preserve ABI stability.
 */

enum
{
  SYS_puts,
#define SYS_puts          SYS_puts
  SYS_thread_exit,
#define SYS_thread_exit   SYS_thread_exit
  SYS_last,
};

#define NR_SYSCALLS   SYS_last

#endif /* SYSCALL_H */
