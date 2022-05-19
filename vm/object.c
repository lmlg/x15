/*
 * Copyright (c) 2017 Richard Braun.
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
 *
 * This implementation is based on the paper "A lockless pagecache in Linux"
 * by Nick Piggin. It allows looking up pages without contention on VM objects.
 */

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include <kern/init.h>
#include <kern/mutex.h>
#include <kern/rcu.h>
#include <kern/rdxtree.h>

#include <vm/object.h>
#include <vm/page.h>

#include <machine/page.h>

struct vm_object vm_object_kernel_object;

static int __init
vm_object_setup (void)
{
  return (0);
}

INIT_OP_DEFINE (vm_object_setup,
                INIT_OP_DEP (mutex_setup, true),
                INIT_OP_DEP (rdxtree_setup, true),
                INIT_OP_DEP (vm_page_setup, true));

void __init
vm_object_init (struct vm_object *object, uint64_t size)
{
  assert (vm_page_aligned (size));

  mutex_init (&object->lock);
  rdxtree_init (&object->pages, 0);
  object->size = size;
  object->nr_pages = 0;
}

int
vm_object_insert (struct vm_object *object, struct vm_page *page,
                  uint64_t offset)
{
  assert (vm_page_aligned (offset));

  /*
   * The page may have no references. Add one before publishing
   * so that concurrent lookups succeed.
   */
  vm_page_ref (page);
  mutex_lock (&object->lock);

  int error;
  if (offset >= object->size)
    {
      error = EINVAL;
      goto error;
    }

  error = rdxtree_insert (&object->pages, vm_page_btop (offset), page);

  if (error)
    goto error;

  vm_page_link (page, object, offset);
  ++object->nr_pages;
  assert (object->nr_pages != 0);

  mutex_unlock (&object->lock);
  return (0);

error:
  mutex_unlock (&object->lock);
  vm_page_unref (page);
  return (error);
}

void
vm_object_remove (struct vm_object *object, uint64_t start, uint64_t end)
{
  assert (vm_page_aligned (start));
  assert (vm_page_aligned (end));
  assert (start <= end);

  mutex_lock (&object->lock);

  for (uint64_t offset = start; offset < end; offset += PAGE_SIZE)
    {
      struct vm_page *page = rdxtree_remove (&object->pages,
                                             vm_page_btop (offset));

      if (! page)
        continue;

      vm_page_unlink (page);
      vm_page_unref (page);
      assert (object->nr_pages != 0);
      --object->nr_pages;
    }

  mutex_unlock (&object->lock);
}

struct vm_page*
vm_object_lookup (struct vm_object *object, uint64_t offset)
{
  rcu_read_enter ();
  int error;
  struct vm_page *page;

  do
    {
      page = rdxtree_lookup (&object->pages, vm_page_btop (offset));
      if (! page)
        break;

      error = vm_page_tryref (page);
    }
  while (error);

  rcu_read_leave ();
  return (page);
}
