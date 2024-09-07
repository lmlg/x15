/*
 * Copyright (c) 2010-2017 Richard Braun.
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
 * Physical page management.
 *
 * A page is said to be managed if it's linked to a VM object, in which
 * case there is at least one reference to it.
 */

#ifndef VM_VM_PAGE_H
#define VM_VM_PAGE_H

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <kern/atomic.h>
#include <kern/init.h>
#include <kern/list.h>
#include <kern/log2.h>
#include <kern/macros.h>
#include <kern/slist_types.h>
#include <kern/spinlock_types.h>
#include <kern/stream.h>

#include <machine/page.h>
#include <machine/pmap.h>
#include <machine/pmem.h>
#include <machine/types.h>

/*
 * Byte/page conversion and rounding macros (not inline functions to
 * be easily usable on both virtual and physical addresses, which may not
 * have the same type size).
 */
#define vm_page_btop(bytes)      ((bytes) >> PAGE_SHIFT)
#define vm_page_ptob(pages)      ((pages) << PAGE_SHIFT)
#define vm_page_trunc(bytes)     P2ALIGN (bytes, PAGE_SIZE)
#define vm_page_round(bytes)     P2ROUND (bytes, PAGE_SIZE)
#define vm_page_end(bytes)       P2END (bytes, PAGE_SIZE)
#define vm_page_aligned(bytes)   P2ALIGNED (bytes, PAGE_SIZE)

/*
 * Zone selectors.
 *
 * Selector-to-zone-list translation table :
 * DMA          DMA
 * DMA32        DMA32 DMA
 * DIRECTMAP    DIRECTMAP DMA32 DMA
 * HIGHMEM      HIGHMEM DIRECTMAP DMA32 DMA
 */
#define VM_PAGE_SEL_DMA         0
#define VM_PAGE_SEL_DMA32       1
#define VM_PAGE_SEL_DIRECTMAP   2
#define VM_PAGE_SEL_HIGHMEM     3

// Page usage types.
#define VM_PAGE_FREE        0   // Page unused.
#define VM_PAGE_RESERVED    1   // Page reserved at boot time.
#define VM_PAGE_TABLE       2   // Page is part of the page table.
#define VM_PAGE_PMAP        3   // Page stores pmap-specific data.
#define VM_PAGE_KMEM        4   // Page is a direct-mapped kmem slab.
#define VM_PAGE_OBJECT      5   // Page is part of a VM object.
#define VM_PAGE_KERNEL      6   // Type for generic kernel allocations.

// Flags passed to the (de)allocation functions.
#define VM_PAGE_SLEEP   0x80

// Page 'cleanliness'.
#define VM_PAGE_CLEAN     0
#define VM_PAGE_DIRTY     1
#define VM_PAGE_LAUNDRY   2

struct vm_object;

// Physical page descriptor.
struct vm_page
{
  union
    {
      struct list node;
      struct slist rset;
    };

  phys_addr_t phys_addr;
  union
    {
      uint32_t whole;
      struct
        {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
          uint8_t type;
          uint8_t zone_index;
          uint8_t order;
          uint8_t dirty;
#else
          uint8_t dirty;
          uint8_t order;
          uint8_t zone_index;
          uint8_t type;
#endif
        };
    };

  uint32_t nr_refs;
  void *priv;

  // VM object back reference.
  struct vm_object *object;
  uint64_t offset;
  // RSET-specific members.
  struct spinlock rset_lock;
};

static inline uint32_t
vm_page_type (const struct vm_page *page)
{
  return (page->type);
}

void vm_page_set_type (struct vm_page *page, uint32_t order, uint16_t type);

static inline uint32_t
vm_page_order (size_t size)
{
  return (log2_order (vm_page_btop (vm_page_round (size))));
}

static inline phys_addr_t
vm_page_to_pa (const struct vm_page *page)
{
  return (page->phys_addr);
}

static inline uintptr_t
vm_page_direct_va (phys_addr_t pa)
{
  assert (pa < PMEM_DIRECTMAP_LIMIT);
  return ((uintptr_t)pa + PMAP_START_DIRECTMAP_ADDRESS);
}

static inline phys_addr_t
vm_page_direct_pa (uintptr_t va)
{
  assert (va >= PMAP_START_DIRECTMAP_ADDRESS);
  assert (va < PMAP_END_DIRECTMAP_ADDRESS);
  return (va - PMAP_START_DIRECTMAP_ADDRESS);
}

static inline void*
vm_page_direct_ptr (const struct vm_page *page)
{
  return ((void *)vm_page_direct_va (vm_page_to_pa (page)));
}

// Associate private data with a page.
static inline void
vm_page_set_priv (struct vm_page *page, void *priv)
{
  page->priv = priv;
}

static inline void*
vm_page_get_priv (const struct vm_page *page)
{
  return (page->priv);
}

static inline void
vm_page_unlink (struct vm_page *page)
{
  assert (page->object);
  page->object = NULL;
}

/*
 * Load physical memory into the vm_page module at boot time.
 *
 * All addresses must be page-aligned. Zones can be loaded in any order.
 */
void vm_page_load (uint32_t zone_index, phys_addr_t start, phys_addr_t end);

/*
 * Load available physical memory into the vm_page module at boot time.
 *
 * The zone referred to must have been loaded with vm_page_load
 * before loading its heap.
 */
void vm_page_load_heap (uint32_t zone_index, phys_addr_t start,
                        phys_addr_t end);

/*
 * Return true if the vm_page module is completely initialized, false
 * otherwise, in which case only vm_page_bootalloc() can be used for
 * allocations.
 */
int vm_page_ready (void);

/*
 * Make the given page managed by the vm_page module.
 *
 * If additional memory can be made usable after the VM system is initialized,
 * it should be reported through this function.
 */
void vm_page_handle (struct vm_page *page);

// Return the page descriptor for the given physical address.
struct vm_page* vm_page_lookup (phys_addr_t pa);

/*
 * Allocate a block of 2^order physical pages.
 *
 * The selector is used to determine the zones from which allocation can
 * be attempted.
 *
 * If successful, the returned pages have no references.
 */
struct vm_page* vm_page_alloc (uint32_t order, uint32_t selector,
                               uint32_t type, uint32_t flags);

/*
 * Release a block of 2^order physical pages.
 *
 * The pages must have no references.
 */
void vm_page_free (struct vm_page *page, uint32_t order, uint32_t flags);

// Deallocate a list of pages.
void vm_page_list_free (struct list *pages);

// Return the name of the given zone.
const char* vm_page_zone_name (uint32_t zone_index);

// Log information about physical pages.
void vm_page_info (struct stream *stream);

// Return the max possible offset for a physical page.
uint64_t vm_page_max_offset (void);

// Clear the contents of a page.
void vm_page_zero (struct vm_page *page);

// Mark a page as being clean.
void vm_page_clean (struct vm_page *page, uint32_t expected);

// Interfaces to manage page cleaning.
void vm_page_wash_begin (struct vm_page *page);
void vm_page_wash_end (struct vm_page *page);

static inline bool
vm_page_referenced (const struct vm_page *page)
{
  return (atomic_load_rlx (&page->nr_refs) != 0);
}

static inline void
vm_page_ref (struct vm_page *page)
{
  uint32_t nr_refs = atomic_add_rlx (&page->nr_refs, 1);
  assert (nr_refs != (uint32_t)-1);
}

static inline bool
vm_page_unref_nofree (struct vm_page *page)
{
  uint32_t nr_refs = atomic_sub_acq_rel (&page->nr_refs, 1);
  assert (nr_refs != 0);
  return (nr_refs == 1);
}

static inline void
vm_page_detach (struct vm_page *page)
{
  void vm_object_detach (struct vm_object *, struct vm_page *);
  vm_object_detach (page->object, page);
  vm_page_unlink (page);
}

static inline void
vm_page_unref (struct vm_page *page)
{
  bool vm_page_can_free (struct vm_page *);
  if (vm_page_unref_nofree (page) && vm_page_can_free (page))
    {
      int flags = page->type == VM_PAGE_OBJECT ? VM_PAGE_SLEEP : 0;
      if (flags == VM_PAGE_SLEEP && page->object)
        vm_page_detach (page);
      vm_page_free (page, 0, flags);
    }
}

static inline int
vm_page_tryref (struct vm_page *page)
{
  while (1)
    {
      uint32_t prev = atomic_load_rlx (&page->nr_refs);
      if (! prev)
        return (EAGAIN);
      else if (atomic_cas_bool_acq (&page->nr_refs, prev, prev + 1))
        return (0);

      atomic_spin_nop ();
    }
}

static inline void
vm_page_set_cow (struct vm_page *page)
{
  uintptr_t prev = (uintptr_t)vm_page_get_priv (page);
  vm_page_set_priv (page, (void *)(prev | 1));
}

static inline void
vm_page_clr_cow (struct vm_page *page)
{
  uintptr_t prev = (uintptr_t)vm_page_get_priv (page);
  vm_page_set_priv (page, (void *)(prev & ~1));
}

static inline bool
vm_page_is_cow (struct vm_page *page)
{
  return (((uintptr_t)vm_page_get_priv (page)) & 1);
}

static inline void
vm_page_init_refcount (struct vm_page *page)
{
  page->nr_refs = 1;
}

static inline uintptr_t
vm_page_anon_va (const struct vm_page *page)
{
  return ((uintptr_t)page->offset);
}

static inline bool
vm_page_mark_dirty (struct vm_page *page)
{
  while (1)
    {
      uint32_t tmp = atomic_load_rlx (&page->whole);
      if ((tmp & 0xff) == VM_PAGE_DIRTY)
        return (false);
      else if (atomic_cas_bool_acq (&page->whole, tmp,
                                    (tmp & ~0xff) | VM_PAGE_DIRTY))
        return (true);

      atomic_spin_nop ();
    }
}

/*
 * This init operation provides :
 *  - module fully initialized
 */
INIT_OP_DECLARE (vm_page_setup);

#endif
