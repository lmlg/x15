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

#include <kern/atomic.h>
#include <kern/init.h>
#include <kern/list_types.h>
#include <kern/rdxtree.h>
#include <kern/spinlock_types.h>
#include <kern/work.h>

struct vm_object;
struct vm_page;
struct cap_channel;
struct cap_page_info;

#define VM_OBJECT_PAGEOUT    0x01   // VM object supports pageouts.
#define VM_OBJECT_EXTERNAL   0x02   // Paging requires IPC to remote task.
#define VM_OBJECT_FLUSHES    0x04   // Pager flushes dirty pages.

struct vm_object
{
  uint32_t refcount;
  union
    {
      struct work work;
      struct
        {
          struct mutex lock;
          struct rdxtree pages;
          uint32_t nr_pages;
          uint32_t flags;
        };
    };
  union
    {
      int (*page_get) (struct vm_object *, uint64_t, size_t, int, void *);
      struct cap_channel *channel;
    };
};

// Initialize a VM object.
void vm_object_init (struct vm_object *object, uint32_t flg, void *ctx);

// Create a VM object.
int vm_object_create (struct vm_object **objp, uint32_t flg, void *ctx);

/*
 * Swap a page in a VM object.
 *
 * If the page doesn't exist at the specified offset, or it matches the
 * passed expected value, the page is inserted and gains a reference.
 *
 * The caller is responsible for making sure the page has at least one
 * reference before this function is called.
 */

int vm_object_swap (struct vm_object *object, struct vm_page *page,
                    uint64_t offset, struct vm_page *expected);

/*
 * Specialized version of the above.
 *
 * Inserting a page is equivalent to swapping a non-existent one.
 */
static inline int
vm_object_insert (struct vm_object *obj, struct vm_page *page, uint64_t off)
{
  return (vm_object_swap (obj, page, off, 0));
}

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
 * Forcefully remove a page from an object.
 *
 * Once a page is inserted into an object, it is kept until its last reference
 * is dropped. Normally, the last reference comes from the object itself, but
 * there are cases where it may not be so. In those cases, it is necessary to
 * call this function to make sure the page is removed from the object.
 */
void vm_object_detach (struct vm_object *object, struct vm_page *page);

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

// Destroy a VM object.
void vm_object_destroy (struct vm_object *object);

// (Un)reference a VM object.
static inline void
vm_object_ref (struct vm_object *object)
{
  uint32_t prev = atomic_add_rlx (&object->refcount, 1);
  assert (prev != ~(uint32_t)0);
}

static inline bool
vm_object_unref_nofree (struct vm_object *object, uint32_t n)
{
  uint32_t prev = atomic_sub_acq_rel (&object->refcount, n);
  assert (prev >= n);
  return (prev == n);
}

static inline void
vm_object_unref_many (struct vm_object *object, uint32_t n)
{
  if (vm_object_unref_nofree (object, n))
    vm_object_destroy (object);
}

static inline void
vm_object_unref (struct vm_object *object)
{
  vm_object_unref_many (object, 1);
}

static inline struct vm_object*
vm_object_tryref (struct vm_object *object)
{
  return (atomic_try_inc (&object->refcount, ATOMIC_ACQUIRE) ? object : NULL);
}

// Create a VM object for anonymous mappings.
int vm_object_anon_create (struct vm_object **outp);

// Store the dirty pages' offsets into a userspace struct.
ssize_t vm_object_list_dirty (struct vm_object *obj, struct cap_page_info *pg);

// Copy an object's pages' contents into a userspace buffer.
ssize_t vm_object_copy_pages (struct vm_object *obj, struct cap_page_info *pg);

// Map dirty pages into userspace.
int vm_object_map_dirty (struct vm_object *obj, struct cap_page_info *pg);

/*
 * This init operation provides :
 * - operations on the kernel VM object
 */
INIT_OP_DECLARE (vm_object_bootstrap);

/*
 * This init operation provides :
 *  - module fully initialized
 */
INIT_OP_DECLARE (vm_object_setup);

#endif
