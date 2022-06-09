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
 * Virtual memory object.
 *
 * The purpose of VM objects is to track pages that are resident in
 * physical memory. They collectively form the page cache.
 */

#ifndef VM_OBJECT_H
#define VM_OBJECT_H

#include <stdint.h>

#include <kern/init.h>
#include <kern/rdxtree.h>

#include <vm/object_types.h>
#include <vm/page.h>

struct vm_object;

static inline struct vm_object*
vm_object_get_kernel_object (void)
{
  extern struct vm_object vm_object_kernel_object;
  return (&vm_object_kernel_object);
}

// Initialize a VM object.
void vm_object_init (struct vm_object *object, uint64_t size,
                     struct vm_object_pager *pager);

/*
 * Insert a page into a VM object.
 *
 * The offset must be page-aligned.
 *
 * The page becomes managed, and gains a reference. If successful,
 * the reference is kept. Otherwise it's dropped. If the page had
 * no references on entry, and a failure occurs, the page is freed.
 */
int vm_object_insert (struct vm_object *object, struct vm_page *page,
                      uint64_t offset);

/*
 * Remove pages from a VM object.
 *
 * The range boundaries must be page-aligned.
 *
 * Holes in the given range are silently skipped. Pages that are removed
 * become unmanaged and lose a reference.
 */
void vm_object_remove (struct vm_object *object, uint64_t start, uint64_t end);

/*
 * Look up a page in a VM object.
 *
 * The offset must be page-aligned.
 *
 * If successful, the returned page gains a reference. Note that, if a valid
 * page is returned, it may already have been removed from the object, or
 * moved at a different offset.
 */
struct vm_page* vm_object_lookup (struct vm_object *object, uint64_t offset);

// Fetch pages' contents from an external pager in a VM object.
int vm_object_pager_get (struct vm_object *object, struct vm_page **pages,
                         int nr_pages);

// Pageout the pages' contents in an external pager for a VM object.
int vm_object_pager_put (struct vm_object *object, struct vm_page **pages,
                         int nr_pages);

/*
 * This init operation provides :
 *  - module fully initialized
 */
INIT_OP_DECLARE (vm_object_setup);

#endif
