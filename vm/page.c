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
 * This implementation uses the binary buddy system to manage its heap.
 * Descriptions of the buddy system can be found in the following works :
 * - "UNIX Internals: The New Frontiers", by Uresh Vahalia.
 * - "Dynamic Storage Allocation: A Survey and Critical Review",
 *    by Paul R. Wilson, Mark S. Johnstone, Michael Neely, and David Boles.
 *
 * In addition, this allocator uses per-CPU pools of pages for order 0
 * (i.e. single page) allocations. These pools act as caches (but are named
 * differently to avoid confusion with CPU caches) that reduce contention on
 * multiprocessor systems. When a pool is empty and cannot provide a page,
 * it is filled by transferring multiple pages from the backend buddy system.
 * The symmetric case is handled likewise.
 */

#include <assert.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <kern/init.h>
#include <kern/list.h>
#include <kern/log.h>
#include <kern/macros.h>
#include <kern/mutex.h>
#include <kern/panic.h>
#include <kern/pqueue.h>
#include <kern/printf.h>
#include <kern/shell.h>
#include <kern/spinlock.h>
#include <kern/thread.h>

#include <machine/boot.h>
#include <machine/cpu.h>
#include <machine/page.h>
#include <machine/pmap.h>
#include <machine/pmem.h>
#include <machine/types.h>

#include <vm/map.h>
#include <vm/page.h>
#include <vm/rset.h>

// Number of free block lists per zone.
#define VM_PAGE_NR_FREE_LISTS   11

/*
 * The size of a CPU pool is computed by dividing the number of pages in its
 * containing zone by this value.
 */
#define VM_PAGE_CPU_POOL_RATIO   1024

// Maximum number of pages in a CPU pool.
#define VM_PAGE_CPU_POOL_MAX_SIZE   128

/*
 * The transfer size of a CPU pool is computed by dividing the pool size by
 * this value.
 */
#define VM_PAGE_CPU_POOL_TRANSFER_RATIO   2

// Per-processor cache of pages.
struct vm_page_cpu_pool
{
  __cacheline_aligned struct mutex lock;
  int size;
  int transfer_size;
  int nr_pages;
  struct list pages;
};

/*
 * Special order value for pages that aren't in a free list. Such pages are
 * either allocated, or part of a free block of pages but not the head page.
 */
#define VM_PAGE_ORDER_UNLISTED   (0xff)

// Doubly-linked list of free blocks.
struct vm_page_free_list
{
  size_t size;
  struct list blocks;
};

// Zone name buffer size.
#define VM_PAGE_NAME_SIZE   16

// Zone of contiguous memory.
struct vm_page_zone
{
  struct vm_page_cpu_pool cpu_pools[CONFIG_MAX_CPUS];
  phys_addr_t start;
  phys_addr_t end;
  struct vm_page *pages;
  struct vm_page *pages_end;
  struct vm_page_free_list free_lists[VM_PAGE_NR_FREE_LISTS];
  size_t nr_free_pages;
  __cacheline_aligned struct mutex lock;
};

// Bootstrap information about a zone.
struct vm_page_boot_zone
{
  phys_addr_t start;
  phys_addr_t end;
  bool heap_present;
  phys_addr_t avail_start;
  phys_addr_t avail_end;
};

// Threads waiting for free object pages.

struct vm_page_waiter
{
  struct thread *thread;
  struct pqueue_node node;
  uint32_t order;
  bool done;
};

struct vm_page_bucket
{
  struct spinlock lock;
  struct pqueue waiters;
};

static int vm_page_is_ready __read_mostly;

/*
 * Zone table.
 *
 * The system supports a maximum of 4 zones :
 *  - DMA: suitable for DMA
 *  - DMA32: suitable for DMA when devices support 32-bits addressing
 *  - DIRECTMAP: direct physical mapping, allows direct access from
 *    the kernel with a simple offset translation
 *  - HIGHMEM: must be mapped before it can be accessed
 *
 * Zones are ordered by priority, 0 being the lowest priority. Their
 * relative priorities are DMA < DMA32 < DIRECTMAP < HIGHMEM. Some zones
 * may actually be aliases for others, e.g. if DMA is always possible from
 * the direct physical mapping, DMA and DMA32 are aliases for DIRECTMAP,
 * in which case the zone table contains DIRECTMAP and HIGHMEM only.
 */
static struct vm_page_zone vm_page_zones[PMEM_MAX_ZONES];

// Bootstrap zone table.
static struct vm_page_boot_zone vm_page_boot_zones[PMEM_MAX_ZONES]
  __initdata;

// Number of loaded zones.
static uint32_t vm_page_zones_size __read_mostly;

// Registry of page_waiters.
static struct vm_page_bucket vm_page_buckets[PMEM_MAX_ZONES];

static void __init
vm_page_init (struct vm_page *page, uint16_t zone_index, phys_addr_t pa)
{
  memset (page, 0, sizeof (*page));
  page->type = VM_PAGE_RESERVED;
  page->zone_index = zone_index;
  page->order = VM_PAGE_ORDER_UNLISTED;
  page->phys_addr = pa;
  page->nr_refs = 0;
  page->object = NULL;
}

void
vm_page_set_type (struct vm_page *page, uint32_t order, uint16_t type)
{
  for (uint32_t i = 0; i < (1u << order); i++)
    {
      page[i].type = type;
      spinlock_init (&page[i].rset_lock);
      list_init (&page[i].node);
    }
}

static void
vm_page_clear (struct vm_page *page, uint32_t order)
{
  for (uint32_t i = 0; i < (1u << order); ++i)
    {
      page[i].type = VM_PAGE_FREE;
      page[i].dirty = 0;
      page[i].priv = NULL;
    }
}

static void __init
vm_page_free_list_init (struct vm_page_free_list *free_list)
{
  free_list->size = 0;
  list_init (&free_list->blocks);
}

static inline void
vm_page_free_list_insert (struct vm_page_free_list *free_list,
                          struct vm_page *page)
{
  assert (page->order == VM_PAGE_ORDER_UNLISTED);
  ++free_list->size;
  list_insert_head (&free_list->blocks, &page->node);
}

static inline void
vm_page_free_list_remove (struct vm_page_free_list *free_list,
                          struct vm_page *page)
{
  assert (page->order != VM_PAGE_ORDER_UNLISTED);
  --free_list->size;
  list_remove (&page->node);
}

static struct vm_page*
vm_page_zone_alloc_from_buddy (struct vm_page_zone *zone, uint32_t order)
{
  struct vm_page_free_list *free_list = free_list;
  assert (order < VM_PAGE_NR_FREE_LISTS);

  uint32_t i;
  for (i = order; i < VM_PAGE_NR_FREE_LISTS; ++i)
    {
      free_list = &zone->free_lists[i];
      if (free_list->size != 0)
        break;
    }

  if (i == VM_PAGE_NR_FREE_LISTS)
    return (NULL);

  _Auto page = list_first_entry (&free_list->blocks, struct vm_page, node);
  vm_page_free_list_remove (free_list, page);
  page->order = VM_PAGE_ORDER_UNLISTED;

  while (i > order)
    {
      i--;
      _Auto buddy = &page[1 << i];
      vm_page_free_list_insert (&zone->free_lists[i], buddy);
      buddy->order = i;
    }

  zone->nr_free_pages -= 1 << order;
  return (page);
}

static void
vm_page_zone_free_to_buddy (struct vm_page_zone *zone, struct vm_page *page,
                            uint32_t order)
{
  assert (page >= zone->pages);
  assert (page < zone->pages_end);
  assert (page->order == VM_PAGE_ORDER_UNLISTED);
  assert (order < VM_PAGE_NR_FREE_LISTS);

  uint32_t nr_pages = 1 << order;
  phys_addr_t pa = page->phys_addr;

  while (order < VM_PAGE_NR_FREE_LISTS - 1)
    {
      phys_addr_t buddy_pa = pa ^ vm_page_ptob (1 << order);

      if (buddy_pa < zone->start || buddy_pa >= zone->end)
        break;

      _Auto buddy = &zone->pages[vm_page_btop (buddy_pa - zone->start)];
      if (buddy->order != order)
        break;

      vm_page_free_list_remove (&zone->free_lists[order], buddy);
      buddy->order = VM_PAGE_ORDER_UNLISTED;
      ++order;
      pa &= -vm_page_ptob (1 << order);
      page = &zone->pages[vm_page_btop (pa - zone->start)];
    }

  vm_page_free_list_insert (&zone->free_lists[order], page);
  page->order = order;
  zone->nr_free_pages += nr_pages;
}

static void __init
vm_page_cpu_pool_init (struct vm_page_cpu_pool *cpu_pool, int size)
{
  mutex_init (&cpu_pool->lock);
  cpu_pool->size = size;
  cpu_pool->transfer_size = (size + VM_PAGE_CPU_POOL_TRANSFER_RATIO - 1) /
                             VM_PAGE_CPU_POOL_TRANSFER_RATIO;
  cpu_pool->nr_pages = 0;
  list_init (&cpu_pool->pages);
}

static inline struct vm_page_cpu_pool*
vm_page_cpu_pool_get (struct vm_page_zone *zone)
{
  return (&zone->cpu_pools[cpu_id ()]);
}

static inline struct vm_page*
vm_page_cpu_pool_pop (struct vm_page_cpu_pool *cpu_pool)
{
  assert (cpu_pool->nr_pages != 0);
  --cpu_pool->nr_pages;
  return (list_pop (&cpu_pool->pages, struct vm_page, node));
}

static inline void
vm_page_cpu_pool_push (struct vm_page_cpu_pool *cpu_pool, struct vm_page *page)
{
  assert (cpu_pool->nr_pages < cpu_pool->size);
  cpu_pool->nr_pages++;
  list_insert_head (&cpu_pool->pages, &page->node);
}

static int
vm_page_cpu_pool_fill (struct vm_page_cpu_pool *cpu_pool,
                       struct vm_page_zone *zone)
{
  assert (cpu_pool->nr_pages == 0);
  MUTEX_GUARD (&zone->lock);

  int i;
  for (i = 0; i < cpu_pool->transfer_size; i++)
    {
      _Auto page = vm_page_zone_alloc_from_buddy (zone, 0);
      if (! page)
        break;

      vm_page_cpu_pool_push (cpu_pool, page);
    }

  return (i);
}

static void
vm_page_cpu_pool_drain (struct vm_page_cpu_pool *cpu_pool,
                        struct vm_page_zone *zone)
{
  assert (cpu_pool->nr_pages == cpu_pool->size);
  MUTEX_GUARD (&zone->lock);

  for (int i = cpu_pool->transfer_size; i > 0; --i)
    {
      _Auto page = vm_page_cpu_pool_pop (cpu_pool);
      vm_page_zone_free_to_buddy (zone, page, 0);
    }
}

static phys_addr_t __init
vm_page_zone_size (struct vm_page_zone *zone)
{
  return (zone->end - zone->start);
}

static int __init
vm_page_zone_compute_pool_size (struct vm_page_zone *zone)
{
  phys_addr_t size = vm_page_btop (vm_page_zone_size (zone)) /
                     VM_PAGE_CPU_POOL_RATIO;
  return (!size ? 1 : MIN (VM_PAGE_CPU_POOL_MAX_SIZE, size));
}

static void __init
vm_page_zone_init (struct vm_page_zone *zone, phys_addr_t start, phys_addr_t end,
                   struct vm_page *pages)
{
  zone->start = start;
  zone->end = end;
  int pool_size = vm_page_zone_compute_pool_size (zone);

  for (uint32_t i = 0; i < ARRAY_SIZE (zone->cpu_pools); ++i)
    vm_page_cpu_pool_init (&zone->cpu_pools[i], pool_size);

  zone->pages = pages;
  zone->pages_end = pages + vm_page_btop (vm_page_zone_size (zone));
  mutex_init (&zone->lock);

  for (uint32_t i = 0; i < ARRAY_SIZE (zone->free_lists); ++i)
    vm_page_free_list_init (&zone->free_lists[i]);

  zone->nr_free_pages = 0;
  uint32_t i = zone - vm_page_zones;

  for (phys_addr_t pa = zone->start; pa < zone->end; pa += PAGE_SIZE)
    vm_page_init (&pages[vm_page_btop (pa - zone->start)], i, pa);
}

static inline int
vm_page_zone_selector (const struct vm_page_zone *zone)
{
  return ((int)(zone - vm_page_zones));
}

static bool
vm_page_wait (struct vm_page_zone *zone, struct mutex *mtx,
              struct vm_page_waiter *waiter)
{
  if (! waiter)
    {
      mutex_unlock (mtx);
      return (false);
    }

  _Auto bucket = &vm_page_buckets[vm_page_zone_selector (zone)];

  // Grab the queue lock before dropping the page pool one.
  SPINLOCK_GUARD (&bucket->lock);
  mutex_unlock (mtx);

  // Test if there are enough free pages before going to sleep.
  if (zone->nr_free_pages >= (1u << waiter->order))
    return (true);
  else if (waiter->order == 0)
    { // Allocating from a CPU pool.
      void *p = (char *)mtx - OFFSETOF (struct vm_page_cpu_pool, lock);
      if (((struct vm_page_cpu_pool *)p)->nr_pages)
        return (true);
    }

  pqueue_insert (&bucket->waiters, &waiter->node);
  thread_sleep (&bucket->lock, bucket, "vm-page");

  pqueue_remove (&bucket->waiters, &waiter->node);
  if (waiter->done)
    // Only bump the other waiters if we succeeded.
    pqueue_inc (&bucket->waiters, 1);

  return (waiter->done);
}

static struct vm_page*
vm_page_zone_alloc (struct vm_page_zone *zone, uint32_t order,
                    uint32_t type, struct vm_page_waiter *waiter)
{
  assert (order < VM_PAGE_NR_FREE_LISTS);

  struct vm_page *page;

  if (! order)
    while (1)
      {
        THREAD_PIN_GUARD ();
        _Auto cpu_pool = vm_page_cpu_pool_get (zone);
        mutex_lock (&cpu_pool->lock);

        if (cpu_pool->nr_pages || vm_page_cpu_pool_fill (cpu_pool, zone))
          {
            page = vm_page_cpu_pool_pop (cpu_pool);
            mutex_unlock (&cpu_pool->lock);
            break;
          }
        else if (!vm_page_wait (zone, &cpu_pool->lock, waiter))
          return (NULL);
      }
  else
    while (1)
      {
        mutex_lock (&zone->lock);
        page = vm_page_zone_alloc_from_buddy (zone, order);

        if (page)
          {
            mutex_unlock (&zone->lock);
            break;
          }
        else if (!vm_page_wait (zone, &zone->lock, waiter))
          return (NULL);
      }

  assert (page->type == VM_PAGE_FREE);
  vm_page_set_type (page, order, type);
  return (page);
}

static bool
vm_page_wakeup (struct vm_page_bucket *bucket, uint32_t order)
{
  SPINLOCK_GUARD (&bucket->lock);
  pqueue_for_each (&bucket->waiters, pnode)
    {
      _Auto waiter = pqueue_entry (pnode, struct vm_page_waiter, node);
      if (likely (waiter->order <= order))
        {
          waiter->done = true;
          thread_wakeup (waiter->thread);
          return (true);
        }
    }

  return (false);
}

static void
vm_page_zone_free (struct vm_page_zone *zone, struct vm_page *page,
                   uint32_t order, uint32_t flags)
{
  assert (page->type != VM_PAGE_FREE);
  assert (order < VM_PAGE_NR_FREE_LISTS);

  vm_page_clear (page, order);

  if (! order)
    {
      THREAD_PIN_GUARD ();
      _Auto cpu_pool = vm_page_cpu_pool_get (zone);
      MUTEX_GUARD (&cpu_pool->lock);

      if (cpu_pool->nr_pages == cpu_pool->size)
        vm_page_cpu_pool_drain (cpu_pool, zone);

      vm_page_cpu_pool_push (cpu_pool, page);
    }
  else
    {
      MUTEX_GUARD (&zone->lock);
      vm_page_zone_free_to_buddy (zone, page, order);
    }

  if (!(flags & VM_PAGE_SLEEP))
    return;

  int selector = vm_page_zone_selector (zone);
  for (; selector >= 0; --selector)
    if (vm_page_wakeup (&vm_page_buckets[selector], order))
      return;
}

void __init
vm_page_load (uint32_t zone_index, phys_addr_t start, phys_addr_t end)
{
  assert (zone_index < ARRAY_SIZE (vm_page_boot_zones));
  assert (vm_page_aligned (start));
  assert (vm_page_aligned (end));
  assert (start < end);
  assert (vm_page_zones_size < ARRAY_SIZE (vm_page_boot_zones));

  _Auto zone = &vm_page_boot_zones[zone_index];
  zone->start = start;
  zone->end = end;
  zone->heap_present = false;

  log_debug ("vm_page: load: %s: %llx:%llx",
             vm_page_zone_name (zone_index), (uint64_t)start, (uint64_t)end);

  ++vm_page_zones_size;
}

void
vm_page_load_heap (uint32_t zone_index, phys_addr_t start, phys_addr_t end)
{
  assert (zone_index < ARRAY_SIZE (vm_page_boot_zones));
  assert (vm_page_aligned (start));
  assert (vm_page_aligned (end));

  _Auto zone = &vm_page_boot_zones[zone_index];

  assert (zone->start <= start);
  assert (end <= zone-> end);

  zone->avail_start = start;
  zone->avail_end = end;
  zone->heap_present = true;

  log_debug ("vm_page: heap: %s: %llx:%llx",
             vm_page_zone_name (zone_index), (uint64_t)start, (uint64_t)end);
}

int
vm_page_ready (void)
{
  return (vm_page_is_ready);
}

static uint32_t
vm_page_select_alloc_zone (uint32_t selector)
{
  uint32_t zone_index;

  switch (selector)
    {
      case VM_PAGE_SEL_DMA:
        zone_index = PMEM_ZONE_DMA;
        break;
      case VM_PAGE_SEL_DMA32:
        zone_index = PMEM_ZONE_DMA32;
        break;
      case VM_PAGE_SEL_DIRECTMAP:
        zone_index = PMEM_ZONE_DIRECTMAP;
        break;
      case VM_PAGE_SEL_HIGHMEM:
        zone_index = PMEM_ZONE_HIGHMEM;
        break;
      default:
        panic ("vm_page: invalid selector");
    }

  return (MIN (vm_page_zones_size - 1, zone_index));
}

static int __init
vm_page_boot_zone_loaded (const struct vm_page_boot_zone *zone)
{
  return (zone->end != 0);
}

static void __init
vm_page_check_boot_zones (void)
{
  if (! vm_page_zones_size)
    panic ("vm_page: no physical memory loaded");

  for (size_t i = 0; i < ARRAY_SIZE (vm_page_boot_zones); i++)
    if (vm_page_boot_zone_loaded (&vm_page_boot_zones[i]) !=
        (i < vm_page_zones_size))
      panic ("vm_page: invalid boot zone table");
}

static phys_addr_t __init
vm_page_boot_zone_size (struct vm_page_boot_zone *zone)
{
  return (zone->end - zone->start);
}

static phys_addr_t __init
vm_page_boot_zone_avail_size (struct vm_page_boot_zone *zone)
{
  return (zone->avail_end - zone->avail_start);
}

static void* __init
vm_page_bootalloc (size_t size)
{
  for (size_t i = vm_page_select_alloc_zone (VM_PAGE_SEL_DIRECTMAP);
       i < vm_page_zones_size; --i)
    {
      _Auto zone = &vm_page_boot_zones[i];

      if (!zone->heap_present)
        continue;
      else if (size <= vm_page_boot_zone_avail_size (zone))
        {
          phys_addr_t pa = zone->avail_start;
          zone->avail_start += vm_page_round (size);
          return ((void *)vm_page_direct_va (pa));
        }
    }

  panic ("vm_page: no physical memory available");
}

#ifdef CONFIG_SHELL

static void
vm_page_shell_info (struct shell *shell, int c __unused, char **v __unused)
{
  vm_page_info (shell->stream);
}

static struct shell_cmd vm_page_shell_cmds[] =
{
  SHELL_CMD_INITIALIZER ("vm_page_info", vm_page_shell_info,
                         "vm_page_info",
                         "display information about physical memory"),
};

static int __init
vm_page_setup_shell (void)
{
  SHELL_REGISTER_CMDS (vm_page_shell_cmds, shell_get_main_cmd_set ());
  return (0);
}

INIT_OP_DEFINE (vm_page_setup_shell,
                INIT_OP_DEP (printf_setup, true),
                INIT_OP_DEP (shell_setup, true),
                INIT_OP_DEP (vm_page_setup, true));

#endif

static int __init
vm_page_setup (void)
{
  vm_page_check_boot_zones ();

  // Compute the page table size.
  size_t nr_pages = 0;

  for (uint32_t i = 0; i < vm_page_zones_size; ++i)
    nr_pages += vm_page_btop (vm_page_boot_zone_size (&vm_page_boot_zones[i]));

  size_t table_size = vm_page_round (nr_pages * sizeof (struct vm_page));
  log_info ("vm_page: page table size: %zu entries (%zuk)",
            nr_pages, table_size >> 10);
  struct vm_page *table = vm_page_bootalloc (table_size);
  uintptr_t va = (uintptr_t) table;

  /*
   * Initialize the zones, associating them to the page table. When
   * the zones are initialized, all their pages are set allocated.
   * Pages are then released, which populates the free lists.
   */
  for (uint32_t i = 0; i < vm_page_zones_size; ++i)
    {
      _Auto zone = &vm_page_zones[i];
      _Auto boot_zone = &vm_page_boot_zones[i];
      vm_page_zone_init (zone, boot_zone->start, boot_zone->end, table);
      _Auto page = zone->pages + vm_page_btop (boot_zone->avail_start -
                                               boot_zone->start);
      _Auto end = zone->pages + vm_page_btop (boot_zone->avail_end -
                                              boot_zone->start);

      for (; page < end; ++page)
        {
          page->type = VM_PAGE_FREE;
          vm_page_zone_free_to_buddy (zone, page, 0);
        }

      table += vm_page_btop (vm_page_zone_size (zone));
    }

  while (va < (uintptr_t) table)
    {
      phys_addr_t pa = vm_page_direct_pa (va);
      struct vm_page *page = vm_page_lookup (pa);
      assert (page && page->type == VM_PAGE_RESERVED);
      page->type = VM_PAGE_TABLE;
      va += PAGE_SIZE;
    }

  for (size_t i = 0; i < ARRAY_SIZE (vm_page_buckets); ++i)
    {
      pqueue_init (&vm_page_buckets[i].waiters);
      spinlock_init (&vm_page_buckets[i].lock);
    }

  vm_page_is_ready = 1;
  return (0);
}

INIT_OP_DEFINE (vm_page_setup,
                INIT_OP_DEP (boot_load_vm_page_zones, true),
                INIT_OP_DEP (log_setup, true),
                INIT_OP_DEP (printf_setup, true));

void __init
vm_page_handle (struct vm_page *page)
{
  assert (page->zone_index < ARRAY_SIZE (vm_page_zones));
  assert (page->type == VM_PAGE_RESERVED);

  vm_page_clear (page, 0);
  vm_page_zone_free_to_buddy (&vm_page_zones[page->zone_index], page, 0);
}

struct vm_page*
vm_page_lookup (phys_addr_t pa)
{
  for (uint32_t i = 0; i < vm_page_zones_size; i++)
    {
      _Auto zone = &vm_page_zones[i];
      if (pa >= zone->start && pa < zone->end)
        return (&zone->pages[vm_page_btop (pa - zone->start)]);
    }

  return (NULL);
}

static bool
vm_page_block_referenced (const struct vm_page *page, uint32_t order)
{
  for (uint32_t i = 0, nr_pages = 1 << order; i < nr_pages; i++)
    if (vm_page_referenced (&page[i]))
      return (true);

  return (false);
}

static void
vm_page_waiter_init (struct vm_page_waiter *wp, uint32_t order)
{
  wp->thread = thread_self ();
  wp->order = order;
  wp->done = false;
  pqueue_node_init (&wp->node, thread_real_global_priority (wp->thread));
}

struct vm_page*
vm_page_alloc (uint32_t order, uint32_t selector,
               uint32_t type, uint32_t flags)
{
  struct vm_page_waiter *waiter = NULL;
  if (flags & VM_PAGE_SLEEP)
    {
      waiter = alloca (sizeof (*waiter));
      vm_page_waiter_init (waiter, order);
    }

  for (uint32_t i = vm_page_select_alloc_zone (selector);
       i < vm_page_zones_size; --i)
    {
      _Auto page = vm_page_zone_alloc (&vm_page_zones[i], order, type, waiter);
      if (page)
        {
          assert (!vm_page_block_referenced (page, order));
          return (page);
        }
    }

  return (NULL);
}

void
vm_page_free (struct vm_page *page, uint32_t order, uint32_t flags)
{
  assert (page->zone_index < ARRAY_SIZE (vm_page_zones));
  assert (!vm_page_block_referenced (page, order));
  vm_page_zone_free (&vm_page_zones[page->zone_index], page, order, flags);
}

void
vm_page_list_free (struct list *pages)
{
  list_for_each_safe (pages, node, tmp)
    {
      _Auto page = list_entry (node, struct vm_page, node);
      vm_page_zone_free (&vm_page_zones[page->zone_index],
                         page, 0, VM_PAGE_SLEEP);
    }
}

const char*
vm_page_zone_name (uint32_t zone_index)
{
  // Don't use a switch statement since zones can be aliased.
  if (zone_index == PMEM_ZONE_HIGHMEM)
    return ("HIGHMEM");
  else if (zone_index == PMEM_ZONE_DIRECTMAP)
    return ("DIRECTMAP");
  else if (zone_index == PMEM_ZONE_DMA32)
    return ("DMA32");
  else if (zone_index == PMEM_ZONE_DMA)
    return ("DMA");
  else
    panic ("vm_page: invalid zone index");
}

uint64_t
vm_page_max_offset (void)
{
  return (vm_page_zones[vm_page_zones_size - 1].end - PAGE_SIZE);
}

void
vm_page_wash_begin (struct vm_page *page)
{
  while (1)
    {
      uint32_t tmp = atomic_load_rlx (&page->whole);
      if ((tmp & 0xff) == VM_PAGE_LAUNDRY ||
          atomic_cas_bool_acq_rel (&page->whole, tmp,
                                   (tmp & ~0xff) | VM_PAGE_LAUNDRY))
        return;

      atomic_spin_nop ();
    }
}

void
vm_page_wash_end (struct vm_page *page)
{
  uint32_t tmp = atomic_load_rlx (&page->whole);
  if ((tmp & 0xff) == VM_PAGE_LAUNDRY &&
      atomic_cas_bool_rlx (&page->whole, tmp, tmp & ~0xff) &&
      !vm_page_referenced (page))
    vm_page_detach (page);
}

void
vm_page_zero (struct vm_page *page)
{
  THREAD_PIN_GUARD ();
  _Auto window = pmap_window_get (0);
  pmap_window_set (window, vm_page_to_pa (page));
  memset (pmap_window_va (window), 0, PAGE_SIZE);
  pmap_window_put (window);
}

void
vm_page_info (struct stream *stream)
{
  for (uint32_t i = 0; i < vm_page_zones_size; ++i)
    {
      _Auto zone = &vm_page_zones[i];
      size_t pages = (size_t) (zone->pages_end - zone->pages);
      fmt_xprintf (stream, "vm_page: %s: pages: %zu (%zuM), "
                   "free: %zu (%zuM)\n",
                   vm_page_zone_name (i), pages, pages >> (20 - PAGE_SHIFT),
                   zone->nr_free_pages,
                   zone->nr_free_pages >> (20 - PAGE_SHIFT));
    }
}
