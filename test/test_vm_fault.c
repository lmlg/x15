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
 *
 * This test module tests page faults and the retrieval of page data
 * from VM objects.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <kern/cpumap.h>
#include <kern/error.h>
#include <kern/init.h>
#include <kern/list.h>
#include <kern/task.h>
#include <kern/thread.h>

#include <machine/page.h>
#include <machine/pmap.h>

#include <test/test.h>

#include <vm/kmem.h>
#include <vm/map.h>
#include <vm/object.h>
#include <vm/page.h>

#define TEST_OFFSET   PAGE_SIZE

static int test_pager_mapped;

static int
test_pager_get (struct vm_object *obj __unused, uint64_t off,
                size_t bytes, void *dst)
{
  assert (! test_pager_mapped);
  assert (off == TEST_OFFSET);
  memset (dst, 'x', bytes);
  test_pager_mapped = 1;
  return (0);
}

static const struct vm_object_pager test_obj_pager =
{
  .get = test_pager_get
};

static void
test_vm_fault_thread (void *arg __unused)
{
  struct vm_object *test_obj;
  int error = vm_object_create (&test_obj, PAGE_SIZE * 4, &test_obj_pager);
  assert (! error);

  uintptr_t va = PMAP_END_ADDRESS - PAGE_SIZE * 10;
  int flags = VM_MAP_FLAGS (VM_PROT_READ, VM_PROT_READ, VM_INHERIT_NONE,
                            VM_ADV_DEFAULT, VM_MAP_FIXED);
  struct vm_map *map = thread_self()->task->map;
  error = vm_map_enter (map, &va, PAGE_SIZE, 0, flags,
                        test_obj, TEST_OFFSET);

  assert (! error);
  // First fault.
  assert (memcmp ((void *)va, "xxx", 3) == 0);
  // This mustn't fault.
  assert (memcmp ((void *)(va + PAGE_SIZE / 2), "xxxx", 4) == 0);

  // Test that writing to read-only mappings fails with EACCES.
  error = vm_copy ((void *)va, "???", 3);
  assert (error == EACCES);

  struct vm_map_entry entry;
  error = vm_map_lookup (map, va, &entry);
  assert (! error);
  assert (entry.object == test_obj);
  assert (VM_MAP_PROT (entry.flags) == VM_PROT_READ);
  vm_map_entry_put (&entry);

  vm_map_remove (map, map->start, map->end);
  vm_object_unref (test_obj);
}

TEST_DEFERRED (vm_fault)
{
  struct task *task;
  int error = task_create (&task, "vm_fault");
  assert (! error);

  struct thread_attr attr;
  thread_attr_init (&attr, "vm_fault/0");
  thread_attr_set_task (&attr, task);

  struct thread *thread;
  thread_create (&thread, &attr, test_vm_fault_thread, 0);
  thread_join (thread);

  int val;
  error = vm_copy (&val, (void *)0x1, sizeof (val));
  assert (error == EFAULT);
  assert (!thread_self()->fixup);

  return (TEST_OK);
}
