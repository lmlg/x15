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

#include <kern/error.h>
#include <kern/init.h>
#include <kern/list.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/user.h>

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
                size_t bytes, int prot __unused, void *dst)
{
  assert (! test_pager_mapped);
  assert (off == TEST_OFFSET);
  memset (dst, 'x', bytes);
  test_pager_mapped = 1;
  return ((int)(bytes >> PAGE_SHIFT));
}

static void
test_vm_fault_forked_entry (void *buf)
{
  atomic_store_seq ((int *)buf, 42);
  assert (*((char *)buf + PAGE_SIZE + 1) == 0);
}

static void
test_vm_fault_forked (struct vm_map *map, void *buf)
{
  struct task *task;
  int error = task_create2 (&task, "vm_fault_forked", map);
  assert (! error);

  struct thread *out;
  struct thread_attr attr;

  thread_attr_init (&attr, "vm_fault_forked/0");
  thread_attr_set_task (&attr, task);

  error = thread_create (&out, &attr, test_vm_fault_forked_entry, buf);
  assert (! error);

  thread_join (out);
}

static void
test_vm_fault_thread (void *arg __unused)
{
  struct vm_object *test_obj;
  int error = vm_object_create (&test_obj, 0, test_pager_get);
  assert (! error);

  uintptr_t va = PMAP_END_ADDRESS - PAGE_SIZE * 10;
  int flags = VM_MAP_FLAGS (VM_PROT_READ, VM_PROT_READ, VM_INHERIT_DEFAULT,
                            VM_ADV_RANDOM, 0);
  struct vm_map *map = vm_map_self ();
  error = vm_map_enter (map, &va, PAGE_SIZE * 3, flags, test_obj, TEST_OFFSET);

  assert (! error);
  // First fault.
  assert (memcmp ((void *)va, "xxx", 3) == 0);
  // This mustn't fault.
  assert (memcmp ((void *)(va + PAGE_SIZE / 2), "xxxx", 4) == 0);

  // Test that writing to read-only mappings fails with EACCES.
  error = user_copy_to ((void *)va, "???", 3);
  assert (error == EACCES);

  // Test that changing protection creates the necessary entries.
  {
    uint32_t nr_entries = vm_map_self()->nr_entries;
    error = vm_map_protect (vm_map_self (), va + PAGE_SIZE,
                            va + PAGE_SIZE * 2, VM_PROT_NONE);
    assert (! error);
    assert (vm_map_self()->nr_entries == nr_entries + 2);

    error = vm_map_protect (vm_map_self (), va + PAGE_SIZE,
                            va + PAGE_SIZE * 2, VM_PROT_READ);
    assert (! error);
    assert (vm_map_self()->nr_entries == nr_entries);
  }

  _Auto entry = vm_map_find (map, va);
  assert (entry);
  assert (entry->object == test_obj);
  assert (VM_MAP_PROT (entry->flags) == VM_PROT_READ);

  {
    void *buf;
    error = vm_map_anon_alloc (&buf, map, PAGE_SIZE * 2);
    assert (! error);
    // Make sure a physical page is allocated.
    atomic_store_seq ((int *)buf, 0);

    struct vm_map *fmap;
    error = vm_map_fork (&fmap, vm_map_self ());
    assert (! error);
    assert (fmap->nr_entries == vm_map_self()->nr_entries);

    _Auto e2 = vm_map_find (fmap, va);
    assert (e2);
    assert (e2 != entry);
    assert (e2->object == entry->object &&
            e2->flags == entry->flags &&
            e2->offset == entry->offset);

    test_vm_fault_forked (fmap, buf);
    vm_map_entry_put (e2);

    // Ensure that COW pages work correctly.
    assert (*(int *)buf == 0);
  }

  vm_map_entry_put (entry);
  vm_object_unref (test_obj);
}

TEST_DEFERRED (vm_fault)
{
  struct thread *thread;
  int error = test_util_create_thr (&thread, test_vm_fault_thread,
                                    NULL, "vm_fault");
  assert (! error);

  int val;
  error = user_copy_to ((void *)0x1, &val, sizeof (val));
  assert (error == EFAULT);
  assert (!thread_self()->fixup);

  thread_join (thread);
  return (TEST_OK);
}
