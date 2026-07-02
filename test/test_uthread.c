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
 * This test module aims to verify that transitions from kernel space to
 * user space are handled correctly, and that user space can perform
 * system calls.
 */

#include <syscall.h>

#include <kern/syscall.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/uthread.h>

#include <machine/syscall.h>

#include <test/test.h>

#include <vm/map.h>
#include <vm/page.h>

struct test_uthread_args
{
  struct vm_page *stack;
  struct vm_page *exe;
  uintptr_t xoff;
};

/*
 * Entry point for the userspace thread.
 *
 * This function is copied to the exe page and executed in user mode.
 * It must be fully position-independent: no relative calls to kernel
 * functions, no PC-relative data accesses. The syscall is issued
 * directly via inline assembly.
 */
static void
test_uthread_entry (void)
{
  SYSCALL_ARCH (SYS_thread_exit, 0, 0);
  __builtin_unreachable ();
}

static void
test_uthread_kthr (void *p)
{
  {
    _Auto uthr = uthread_allocate ();
    test_assert_nonnull (uthr);
    thread_self()->uthread = uthr;
  }

  _Auto args = (struct test_uthread_args *)p;
  int flags = VM_MAP_FLAGS (VM_PROT_RDWR, VM_PROT_RDWR,
                            VM_INHERIT_NONE, VM_ADV_DEFAULT,
                            VM_MAP_PHYS);
  uintptr_t stack = 0;
  int error = vm_map_enter (vm_map_self (), &stack, PAGE_SIZE, flags,
                            0, vm_page_to_pa (args->stack));
  test_assert_zero (error);

  flags = VM_MAP_FLAGS (VM_PROT_EXEC | VM_PROT_READ,
                        VM_PROT_EXEC | VM_PROT_READ,
                        VM_INHERIT_NONE, VM_ADV_DEFAULT, VM_MAP_PHYS);
  uintptr_t xf = 0;
  error = vm_map_enter (vm_map_self (), &xf, PAGE_SIZE, flags,
                        0, vm_page_to_pa (args->exe));
  test_assert_zero (error);

  { // Install the TID pointer.
    int *ptr = (int *)stack;
    *ptr = thread_id (thread_self ());
    thread_self()->uthread->tid = ptr;
  }

  thread_suspend (thread_self ());
  syscall_jump_to_user (xf + args->xoff,
                        stack + PAGE_SIZE - sizeof (uintptr_t));
}

static uintptr_t
test_uthread_xcopy (struct vm_page *dst, uintptr_t fn)
{
  uintptr_t start = fn & ~(PAGE_SIZE - 1);
  memcpy (vm_page_direct_ptr (dst), (void *)start, PAGE_SIZE);
  return (fn - start);
}

TEST_DEFERRED (uthread)
{
  struct test_uthread_args args;

  args.stack = vm_page_alloc (1, VM_PAGE_SEL_DIRECTMAP, VM_PAGE_KERNEL, 0);
  test_assert_nonnull (args.stack);
  args.exe = args.stack + 1;

  void *pptr = vm_page_direct_ptr (args.stack);
  args.xoff = test_uthread_xcopy (args.exe, (uintptr_t)test_uthread_entry);

  struct thread *kthr;
  int err = test_util_create_thr (&kthr, test_uthread_kthr, &args, "uthread");
  test_assert_zero (err);

  test_thread_wait_state (kthr, THREAD_SUSPENDED);
  test_assert_eq (thread_id (kthr), *(int *)pptr);

  thread_resume (kthr);
  thread_join (kthr);
  test_assert_zero (*(int *)pptr);
  vm_page_unref (args.stack);
  vm_page_unref (args.exe);

  return (TEST_OK);
}
