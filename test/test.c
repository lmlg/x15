/*
 * Copyright (c) 2022 Agustina Arzille.
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
#include <stdio.h>
#include <string.h>

#include <kern/fmt.h>
#include <kern/log.h>
#include <kern/macros.h>
#include <kern/symbol.h>
#include <kern/task.h>
#include <kern/thread.h>

#include <machine/cpu.h>
#include <machine/pmap.h>
#include <machine/syscall.h>

#include <test/test.h>

#include <vm/map.h>
#include <vm/page.h>

#define PREFIX_LEN   (sizeof (QUOTE (TEST_PREFIX)) - 1)

typedef int (*test_fn_t) (void);

static bool
test_is_inline (const char *name)
{
  return (name[PREFIX_LEN] == QUOTE(TEST_INLINE_CHAR)[0]);
}

static const char*
test_exit_status (int ret)
{
  switch (ret)
    {
      case TEST_OK:
        return ("OK");
      case TEST_SKIPPED:
        return ("skipped");
      case TEST_RUNNING:
        return ("running");
      case TEST_FAILED:
        return ("failed");
      default:
        panic ("unsupported test type");
        return (NULL);
    }
}

static void
test_thread_run (void *arg)
{
  const struct symbol *sym = arg;
  int ret = ((test_fn_t)sym->addr) ();
  const char *name = sym->name + PREFIX_LEN +
                     (test_is_inline (sym->name) ? 2 : 1);
  log_info ("test (%s): %s", name, test_exit_status (ret));
}

void
test_setup (void)
{
  struct symbol_iter iter;

  for (symbol_iter_init (&iter);
      symbol_iter_valid (&iter);
      symbol_iter_next (&iter))
    {
      const struct symbol *sym = iter.symbol;

      if ((uintptr_t)sym->name < PMAP_START_KERNEL_ADDRESS ||
          (uintptr_t)sym->name > PMAP_END_KERNEL_ADDRESS)
        /*
         * This can happen for symbols that live in the BOOT section;
         * at this stage, that memory is no longer accessible, so we
         * simply skip them.
         */
        continue;

      size_t len = strlen (sym->name);

      if (len <= PREFIX_LEN ||
          memcmp (sym->name, QUOTE (TEST_PREFIX), PREFIX_LEN) != 0)
        continue;
      else if (test_is_inline (sym->name))
        {
          test_thread_run ((void *)sym);
          continue;
        }

      char name[THREAD_NAME_SIZE];
      snprintf (name, sizeof (name), THREAD_KERNEL_PREFIX "test_%s",
                sym->name + PREFIX_LEN + 1);

      struct thread_attr attr;
      thread_attr_init (&attr, name);
      thread_attr_set_detached (&attr);

      if (thread_create (NULL, &attr, test_thread_run, (void *)sym) != 0)
        log_err ("failed to run test: %s", attr.name);
    }
}

int
test_util_create_thr (struct thread **out, void (*fn) (void *),
                      void *arg, const char *name)
{
  struct task *task;
  int error = task_create (&task, name);
  if (error)
    return (error);

  char tname[TASK_NAME_SIZE];
  sprintf (tname, "%s/0", name);

  struct thread_attr attr;
  thread_attr_init (&attr, tname);
  thread_attr_set_task (&attr, task);

  error = thread_create (out, &attr, fn, arg);
  if (error)
    task_destroy (task);

  return (error);
}

void
test_thread_wait_state (struct thread *thr, uint32_t state)
{
  while (thread_state (thr) != state)
    thread_yield ();
}

int
test_util_create_utask (struct test_utask *out, const char *name)
{
  int err = task_create (&out->ktask, name);
  if (err)
    return (err);

  out->data = vm_page_alloc (0, VM_PAGE_SEL_DIRECTMAP, VM_PAGE_KERNEL, 0);
  if (!out->data)
    {
      task_destroy (out->ktask);
      return (ENOMEM);
    }

  vm_page_init_refcount (out->data);

  uintptr_t udata = 0;
  int flags = VM_MAP_FLAGS (VM_PROT_RDWR, VM_PROT_RDWR,
                            VM_INHERIT_DEFAULT, VM_ADV_DEFAULT, VM_MAP_PHYS);
  err = vm_map_enter (out->ktask->map, &udata, PAGE_SIZE, flags,
                      0, vm_page_to_pa (out->data));
  if (err)
    {
      vm_page_unref (out->data);
      task_destroy (out->ktask);
      return (err);
    }

  task_ref (out->ktask);
  out->num_thr = 0;
  out->data_cur = (char *)udata;
  out->data_end = out->data_cur + PAGE_SIZE;
  return (0);
}

void*
test_util_utask_reserve (struct test_utask *out, size_t size)
{
  size = (size + sizeof (uintptr_t) - 1) & ~(sizeof (uintptr_t) - 1);
  char *ret = out->data_cur;

  if (out->data_end - ret < (long)size)
    return (0);

  out->data_cur += size;
  return (ret);
}

struct test_uthread_karg
{
  volatile int status;
  uintptr_t entry;
  uintptr_t uctl;
  void *uarg;
  struct test_uthread *thr;
  void (*prepare) (uintptr_t, void *);
};

static void
test_util_kentry (void *arg)
{
  struct test_uthread_karg *karg = arg;
  struct vm_page *stack = 0, *exec = 0;

  if (!(thread_self()->uthread = uthread_allocate ()))
    goto error;

  stack = vm_page_alloc (0, VM_PAGE_SEL_DIRECTMAP, VM_PAGE_KERNEL, 0);
  if (! stack)
    goto error;

  vm_page_init_refcount (stack);
  exec = vm_page_alloc (0, VM_PAGE_SEL_DIRECTMAP, VM_PAGE_KERNEL, 0);
  if (! exec)
    goto error;

  vm_page_init_refcount (exec);

  /*
   * At the top of the stack lies the control block, through which userspace
   * can communicate failures to the kernel thread.
   * Right below that is the argument for the userspace thread.
   */
  _Auto sp_end = (char *)vm_page_direct_ptr (stack) + PAGE_SIZE -
                 sizeof (struct test_uctl) - sizeof (uintptr_t);
  *(uintptr_t *)sp_end = (uintptr_t)karg->uarg;

  uintptr_t uentry = karg->entry & ~(PAGE_SIZE - 1);
  memcpy (vm_page_direct_ptr (exec), (void *)uentry, PAGE_SIZE);

  int flags = VM_MAP_FLAGS (VM_PROT_RDWR, VM_PROT_RDWR,
                            VM_INHERIT_DEFAULT, VM_ADV_DEFAULT, VM_MAP_PHYS);
  uintptr_t sp = 0, pc = 0;
  if (vm_map_enter (vm_map_self (), &sp, PAGE_SIZE, flags,
                    0, vm_page_to_pa (stack)) != 0)
    goto error;

  flags = VM_MAP_FLAGS (VM_PROT_READ | VM_PROT_EXEC,
                        VM_PROT_READ | VM_PROT_EXEC,
                        VM_INHERIT_DEFAULT, VM_ADV_DEFAULT, VM_MAP_PHYS);
  if (vm_map_enter (vm_map_self (), &pc, PAGE_SIZE, flags,
                    0, vm_page_to_pa (exec)) != 0)
    goto error;

  pc += karg->entry - uentry;
  karg->thr->stack = stack;
  karg->thr->exec = exec;
  if (karg->prepare)
    karg->prepare (pc, (void *)karg->uarg);

  atomic_store_rel (&karg->status, 1);
  syscall_jump_to_user (pc, sp + PAGE_SIZE - sizeof (struct test_uctl) -
                            2 * sizeof (uintptr_t));
  return;

error:
  if (stack)
    vm_page_unref (stack);
  if (exec)
    vm_page_unref (exec);

  atomic_store_rel (&karg->status, -1);
}

int
test_util_create_uthr (struct test_uthread *out,
                       const struct test_uthread_attr *attr,
                       uintptr_t entry, void *arg)
{
  assert ((entry & ~(PAGE_SIZE - 1)) + PAGE_SIZE >= entry + attr->fnsize);

  struct test_uthread_karg karg;
  karg.status = 0;
  karg.entry = entry;
  karg.thr = out;
  karg.uarg = arg;
  karg.prepare = attr->prepare;

  struct thread_attr kattr;
  _Auto task = attr->task;
  char buf[32];
  snprintf (buf, sizeof (buf), "%s/%u", task->ktask->name, ++task->num_thr);

  thread_attr_init (&kattr, buf);
  thread_attr_set_task (&kattr, task->ktask);

  int error = thread_create (&out->kthr, &kattr, test_util_kentry, &karg);
  if (error)
    return (error);

  out->utask = task;
  while (atomic_load_acq (&karg.status) == 0)
    thread_yield ();

  if (karg.status < 0)
    {
      thread_join (out->kthr);
      return (ENOMEM);
    }

  return (0);
}

int
test_util_uthr_join (struct test_uthread *uthr)
{
  char name[THREAD_NAME_SIZE];
  memcpy (name, uthr->kthr->name, sizeof (name));

  _Auto task = uthr->utask->ktask;
  thread_join (uthr->kthr);
  _Auto uctl = (struct test_uctl *)((char *)vm_page_direct_ptr (uthr->stack) +
                                    PAGE_SIZE - sizeof (struct test_uctl));
  if (uctl->failure)
    panic ("user thread %s failed at line %d (%lu-%lu)",
           name, uctl->line, uctl->arg1, uctl->arg2);

  vm_page_unref (uthr->stack);
  vm_page_unref (uthr->exec);

  int ret = 0;
  if (!task->map)
    { // This was the last thread in the task.
      vm_page_unref (uthr->utask->data);
      ret = task->terminate;
      task_unref (task);
    }

  return (ret);
}
