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

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <syscall.h>

#include <kern/init.h>
#include <kern/macros.h>
#include <kern/syscall.h>
#include <kern/syscall_i.h>
#include <kern/task.h>

#include <machine/syscall.h>

#include <vm/map.h>

INIT_OP_DECLARE (cpu_setup);

SYSCALL_STATIC (puts, const char *str)
{
  printf ("%s", str);
  return (0);
}

SYSCALL_STATIC (thread_exit, void *mem, size_t len)
{
  if (mem)
    {
      uintptr_t start = (uintptr_t)mem;
      vm_map_remove (vm_map_self (), start, start + len);
    }

  thread_exit ();
  __builtin_unreachable ();
}

/*
 * System call table.
 *
 * Indexed by syscall number. NULL entries return -ENOSYS.
 */

static const syscall_fn_t syscall_table[NR_SYSCALLS] =
{
#define SYSCALL_E(name)   [SYS_##name] = sys_##name
  SYSCALL_E (puts),
  SYSCALL_E (thread_exit),
#undef SYSCALL_E
};


ssize_t
syscall_dispatch (uintptr_t nr, const uintptr_t args[6])
{
  if (nr >= ARRAY_SIZE (syscall_table) || syscall_table[nr] == NULL)
    return (-ENOSYS);

  return (syscall_table[nr] (args[0], args[1], args[2],
                             args[3], args[4], args[5]));
}

int __init
syscall_setup (void)
{
  syscall_arch_init ();
  return (0);
}

INIT_OP_DEFINE (syscall_setup,
                INIT_OP_DEP (cpu_setup, true));

void
syscall_enter (struct cpu_exc_frame *frame __unused)
{
  // Capture/log transition to kernel space via system call.
}

void
syscall_interrupt_enter (struct cpu_exc_frame *frame __unused)
{
  // Capture/log transition to kernel space via interrupt or exception.
}
