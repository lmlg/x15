/*
 * Copyright (c) 2010-2018 Richard Braun.
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
 * This allocator is based on the paper "The Slab Allocator: An Object-Caching
 * Kernel Memory Allocator" by Jeff Bonwick.
 *
 * It allows the allocation of objects (i.e. fixed-size typed buffers) from
 * caches and is efficient in both space and time. This implementation follows
 * many of the indications from the paper mentioned. The most notable
 * differences are outlined below.
 *
 * The per-cache self-scaling hash table for buffer-to-bufctl conversion,
 * described in 3.2.3 "Slab Layout for Large Objects", has been replaced with
 * a constant time buffer-to-slab lookup that relies on the VM system.
 *
 * Slabs are allocated from the physical page allocator if they're page-sized,
 * and from kernel virtual memory if they're bigger, in order to prevent
 * physical memory fragmentation from making slab allocations fail.
 *
 * This implementation uses per-CPU pools of objects, which service most
 * allocation requests. These pools act as caches (but are named differently
 * to avoid confusion with CPU caches) that reduce contention on multiprocessor
 * systems. When a pool is empty and cannot provide an object, it is filled by
 * transferring multiple objects from the slab layer. The symmetric case is
 * handled likewise.
 *
 * TODO Rework the CPU pool layer to use the SLQB algorithm by Nick Piggin.
 */

#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <kern/adaptive_lock.h>
#include <kern/init.h>
#include <kern/list.h>
#include <kern/log.h>
#include <kern/log2.h>
#include <kern/kmem.h>
#include <kern/macros.h>
#include <kern/panic.h>
#include <kern/shell.h>
#include <kern/thread.h>
#include <machine/cpu.h>
#include <machine/page.h>
#include <machine/pmap.h>
#include <vm/kmem.h>
#include <vm/page.h>

// Minimum required alignment.
#define KMEM_ALIGN_MIN   8

/*
 * Minimum number of buffers per slab.
 *
 * This value is ignored when the slab size exceeds a threshold.
 */
#define KMEM_MIN_BUFS_PER_SLAB   8

/*
 * Special slab size beyond which the minimum number of buffers per slab is
 * ignored when computing the slab size of a cache.
 */
#define KMEM_SLAB_SIZE_THRESHOLD   (8 * PAGE_SIZE)

/*
 * Special buffer size under which slab data is unconditionally allocated
 * from its associated slab.
 */
#define KMEM_BUF_SIZE_THRESHOLD   (PAGE_SIZE / 8)

/*
 * The transfer size of a CPU pool is computed by dividing the pool size by
 * this value.
 */
#define KMEM_CPU_POOL_TRANSFER_RATIO   2

// Logarithm of the size of the smallest general cache.
#define KMEM_CACHES_FIRST_ORDER 5

// Number of caches backing general purpose allocations.
#define KMEM_NR_MEM_CACHES 13

// Options for kmem_cache_alloc_verify().
#define KMEM_AV_NOCONSTRUCT   0
#define KMEM_AV_CONSTRUCT     1

// Error codes for kmem_cache_error().
#define KMEM_ERR_INVALID      0   // Invalid address being freed
#define KMEM_ERR_DOUBLEFREE   1   // Freeing already free address
#define KMEM_ERR_BUFTAG       2   // Invalid buftag content
#define KMEM_ERR_MODIFIED     3   // Buffer modified while free
#define KMEM_ERR_REDZONE      4   // Redzone violation

#ifdef KMEM_USE_CPU_LAYER

/*
 * Available CPU pool types.
 *
 * For each entry, the CPU pool size applies from the entry buf_size
 * (excluded) up to (and including) the buf_size of the preceding entry.
 *
 * See struct kmem_cpu_pool_type for a description of the values.
 */
static struct kmem_cpu_pool_type kmem_cpu_pool_types[] __read_mostly =
{
  {  32768,   1, 0,           NULL },
  {   4096,   8, CPU_L1_SIZE, NULL },
  {    256,  64, CPU_L1_SIZE, NULL },
  {      0, 128, CPU_L1_SIZE, NULL }
};

// Caches where CPU pool arrays are allocated from.
#define KMEM_CPU_ARRAY_CACHE_SIZE   ARRAY_SIZE (kmem_cpu_pool_types)
static struct kmem_cache kmem_cpu_array_caches[KMEM_CPU_ARRAY_CACHE_SIZE];

#endif

// Cache for off slab data.
static struct kmem_cache kmem_slab_cache;

// General caches array.
static struct kmem_cache kmem_caches[KMEM_NR_MEM_CACHES];

// List of all caches managed by the allocator.
static struct list kmem_cache_list;
static struct adaptive_lock kmem_cache_list_lock;

static void kmem_cache_error (struct kmem_cache *cache, void *buf, int error,
                              void *arg);
static void* kmem_cache_alloc_from_slab (struct kmem_cache *cache);
static void kmem_cache_free_to_slab (struct kmem_cache *cache, void *buf);

static void*
kmem_buf_verify_bytes (void *buf, void *pattern, size_t size)
{
  char *end = buf + size;
  for (char *ptr = buf, *pattern_ptr = pattern;
      ptr < end; ptr++, pattern_ptr++)
    if (*ptr != *pattern_ptr)
      return (ptr);

  return (NULL);
}

static void
kmem_buf_fill (void *buf, uint64_t pattern, size_t size)
{
  assert (P2ALIGNED ((uintptr_t) buf, sizeof (uint64_t)));
  assert (P2ALIGNED (size, sizeof (uint64_t)));

  uint64_t *end = (uint64_t *)((char *)buf + size);

  for (uint64_t *ptr = buf; ptr < end; ptr++)
    *ptr = pattern;
}

static void *
kmem_buf_verify_fill (void *buf, uint64_t old, uint64_t new, size_t size)
{
  assert (P2ALIGNED ((uintptr_t) buf, sizeof (uint64_t)));
  assert (P2ALIGNED (size, sizeof (uint64_t)));

  uint64_t *end = (uint64_t *)((char *)buf + size);

  for (uint64_t *ptr = buf; ptr < end; ptr++)
    {
      if (*ptr != old)
        return (kmem_buf_verify_bytes (ptr, &old, sizeof (old)));

      *ptr = new;
    }

  return (NULL);
}

static inline union kmem_bufctl*
kmem_buf_to_bufctl (void *buf, struct kmem_cache *cache)
{
  return ((union kmem_bufctl *)(buf + cache->bufctl_dist));
}

static inline struct kmem_buftag*
kmem_buf_to_buftag (void *buf, struct kmem_cache *cache)
{
  return ((struct kmem_buftag *)(buf + cache->buftag_dist));
}

static inline void*
kmem_bufctl_to_buf (union kmem_bufctl *bufctl, struct kmem_cache *cache)
{
  return ((char *)bufctl - cache->bufctl_dist);
}

static inline bool
kmem_pagealloc_is_virtual (size_t size)
{
  return (size > PAGE_SIZE);
}

static void*
kmem_pagealloc (size_t size)
{
  if (kmem_pagealloc_is_virtual (size))
    return (vm_kmem_alloc (size));

  _Auto page = vm_page_alloc (vm_page_order (size), VM_PAGE_SEL_DIRECTMAP,
                              VM_PAGE_KMEM);
  return (page ? vm_page_direct_ptr (page) : NULL);
}

static void
kmem_pagefree (void *ptr, size_t size)
{
  if (kmem_pagealloc_is_virtual (size) )
    vm_kmem_free (ptr, size);
  else
    {
      _Auto page = vm_page_lookup (vm_page_direct_pa ((uintptr_t)ptr));
      assert (page);
      vm_page_free (page, vm_page_order (size));
    }
}

static void
kmem_slab_create_verify (struct kmem_slab *slab, struct kmem_cache *cache)
{
  size_t buf_size = cache->buf_size;
  void *buf = slab->addr;
  _Auto buftag = kmem_buf_to_buftag (buf, cache);

  for (size_t buffers = cache->bufs_per_slab; buffers; --buffers)
    {
      kmem_buf_fill (buf, KMEM_FREE_PATTERN, cache->bufctl_dist);
      buftag->state = KMEM_BUFTAG_FREE;
      buf += buf_size;
      buftag = kmem_buf_to_buftag (buf, cache);
    }
}

/*
 * Create an empty slab for a cache.
 *
 * The caller must drop all locks before calling this function.
 */
static struct kmem_slab*
kmem_slab_create (struct kmem_cache *cache, size_t color)
{
  void *slab_buf = kmem_pagealloc (cache->slab_size);
  if (! slab_buf)
    return (NULL);

  struct kmem_slab *slab;
  if (cache->flags & KMEM_CF_SLAB_EXTERNAL)
    {
      slab = kmem_cache_alloc (&kmem_slab_cache);
      if (! slab)
        {
          kmem_pagefree (slab_buf, cache->slab_size);
          return (NULL);
        }
    }
  else
    slab = (struct kmem_slab *) ((char *)slab_buf + cache->slab_size) - 1;

  list_node_init (&slab->node);
  slab->nr_refs = 0;
  slab->first_free = NULL;
  slab->addr = slab_buf + color;

  size_t buf_size = cache->buf_size;
  _Auto bufctl = kmem_buf_to_bufctl (slab->addr, cache);

  for (size_t buffers = cache->bufs_per_slab; buffers; --buffers)
    {
      bufctl->next = slab->first_free;
      slab->first_free = bufctl;
      bufctl = (union kmem_bufctl *)((char *) bufctl + buf_size);
    }

  if (cache->flags & KMEM_CF_VERIFY)
    kmem_slab_create_verify (slab, cache);

  return (slab);
}

static inline uintptr_t
kmem_slab_buf (const struct kmem_slab *slab)
{
  return (P2ALIGN ((uintptr_t)slab->addr, PAGE_SIZE));
}

#ifdef KMEM_USE_CPU_LAYER

static void
kmem_cpu_pool_init (struct kmem_cpu_pool *cpu_pool, struct kmem_cache *cache)
{
  adaptive_lock_init (&cpu_pool->lock);
  cpu_pool->flags = cache->flags;
  cpu_pool->size = 0;
  cpu_pool->transfer_size = 0;
  cpu_pool->nr_objs = 0;
  cpu_pool->array = NULL;
}

static inline struct kmem_cpu_pool*
kmem_cpu_pool_get (struct kmem_cache *cache)
{
  return (&cache->cpu_pools[cpu_id ()]);
}

static inline void
kmem_cpu_pool_build (struct kmem_cpu_pool *cpu_pool, struct kmem_cache *cache,
                     void **array)
{
  cpu_pool->size = cache->cpu_pool_type->array_size;
  cpu_pool->transfer_size = (cpu_pool->size +
                             KMEM_CPU_POOL_TRANSFER_RATIO - 1) /
                            KMEM_CPU_POOL_TRANSFER_RATIO;
  cpu_pool->array = array;
}

static inline void*
kmem_cpu_pool_pop (struct kmem_cpu_pool *cpu_pool)
{
  return (cpu_pool->array[--cpu_pool->nr_objs]);
}

static inline void
kmem_cpu_pool_push (struct kmem_cpu_pool *cpu_pool, void *obj)
{
  cpu_pool->array[cpu_pool->nr_objs++] = obj;
}

static int
kmem_cpu_pool_fill (struct kmem_cpu_pool *cpu_pool, struct kmem_cache *cache)
{
  kmem_ctor_fn_t ctor = (cpu_pool->flags & KMEM_CF_VERIFY) ?
                        NULL : cache->ctor;

  ADAPTIVE_LOCK_GUARD (&cache->lock);

  int i;
  for (i = 0; i < cpu_pool->transfer_size; i++)
    {
      void *buf = kmem_cache_alloc_from_slab (cache);
      if (! buf)
        break;
      else if (ctor)
        ctor (buf);

      kmem_cpu_pool_push (cpu_pool, buf);
    }

  return (i);
}

static void
kmem_cpu_pool_drain (struct kmem_cpu_pool *cpu_pool, struct kmem_cache *cache)
{
  ADAPTIVE_LOCK_GUARD (&cache->lock);
  for (int i = cpu_pool->transfer_size; i > 0; i--)
    {
      void *obj = kmem_cpu_pool_pop (cpu_pool);
      kmem_cache_free_to_slab (cache, obj);
    }
}

#endif // KMEM_USE_CPU_LAYER

static void
kmem_cache_error (struct kmem_cache *cache, void *buf, int error, void *arg)
{
  printf_ln ("kmem: error: cache: %s, buffer: %p", cache->name, buf);
  switch (error)
    {
      case KMEM_ERR_INVALID:
        panic ("kmem: freeing invalid address");
        break;
      case KMEM_ERR_DOUBLEFREE:
        panic ("kmem: attempting to free the same address twice");
        break;
      case KMEM_ERR_BUFTAG:
        panic ("kmem: invalid buftag content, buftag state: %p",
               (void *)((struct kmem_buftag *)arg)->state);
        break;
      case KMEM_ERR_MODIFIED:
        panic ("kmem: free buffer modified, fault address: %p, "
               "offset in buffer: %td", arg, arg - buf);
        break;
      case KMEM_ERR_REDZONE:
        panic ("kmem: write beyond end of buffer, fault address: %p, "
               "offset in buffer: %td", arg, arg - buf);
        break;
      default:
        panic ("kmem: unknown error");
    }

  __builtin_unreachable ();
}

/*
 * Compute properties such as slab size for the given cache.
 *
 * Once the slab size is known, this function sets the related properties
 * (buffers per slab and maximum color). It can also set some KMEM_CF_xxx
 * flags depending on the resulting layout.
 */
static void
kmem_cache_compute_properties (struct kmem_cache *cache, int flags)
{
  if (cache->buf_size < KMEM_BUF_SIZE_THRESHOLD)
    flags |= KMEM_CACHE_NOOFFSLAB;

  cache->slab_size = PAGE_SIZE;

  bool embed;
  size_t size;

  while (1)
    {
      if (flags & KMEM_CACHE_NOOFFSLAB)
        embed = true;
      else
        {
          size_t waste = cache->slab_size % cache->buf_size;
          embed = (sizeof (struct kmem_slab) <= waste);
        }

      size = cache->slab_size;

      if (embed)
        size -= sizeof (struct kmem_slab);

      if (size >= cache->buf_size)
        break;

      cache->slab_size += PAGE_SIZE;
    }

  /*
   * A user may force page allocation in order to guarantee that virtual
   * memory isn't used. This is normally done for objects that are used
   * to implement virtual memory and avoid circular dependencies.
   *
   * When forcing the use of direct page allocation, only allow single
   * page allocations in order to completely prevent physical memory
   * fragmentation from making slab allocations fail.
   */
  if ((flags & KMEM_CACHE_PAGE_ONLY) && cache->slab_size != PAGE_SIZE)
    panic ("kmem: unable to guarantee page allocation");

  cache->bufs_per_slab = size / cache->buf_size;
  cache->color_max = size % cache->buf_size;

  /*
   * Make sure the first page of a slab buffer can be found from the
   * address of the first object.
   *
   * See kmem_slab_buf().
   */
  if (cache->color_max >= PAGE_SIZE)
    cache->color_max = 0;

  if (!embed)
    cache->flags |= KMEM_CF_SLAB_EXTERNAL;
}

void
kmem_cache_init (struct kmem_cache *cache, const char *name, size_t obj_size,
                 size_t align, kmem_ctor_fn_t ctor, int flags)
{
#ifdef CONFIG_KMEM_DEBUG
  cache->flags = KMEM_CF_VERIFY;
#else
  cache->flags = 0;
#endif

  if (flags & KMEM_CACHE_VERIFY)
    cache->flags |= KMEM_CF_VERIFY;

  if (align < KMEM_ALIGN_MIN)
    align = KMEM_ALIGN_MIN;

  assert (obj_size > 0);
  assert (ISP2 (align) );
  assert (align < PAGE_SIZE);

  size_t buf_size = P2ROUND (obj_size, align);

  adaptive_lock_init (&cache->lock);
  list_node_init (&cache->node);
  list_init (&cache->partial_slabs);
  list_init (&cache->free_slabs);
  cache->obj_size = obj_size;
  cache->align = align;
  cache->buf_size = buf_size;
  cache->bufctl_dist = buf_size - sizeof (union kmem_bufctl);
  cache->color = 0;
  cache->nr_objs = 0;
  cache->nr_bufs = 0;
  cache->nr_slabs = 0;
  cache->nr_free_slabs = 0;
  cache->ctor = ctor;
  strlcpy (cache->name, name, sizeof (cache->name) );
  cache->buftag_dist = 0;
  cache->redzone_pad = 0;

  if (cache->flags & KMEM_CF_VERIFY)
    {
      cache->bufctl_dist = buf_size;
      cache->buftag_dist = cache->bufctl_dist + sizeof (union kmem_bufctl);
      cache->redzone_pad = cache->bufctl_dist - cache->obj_size;
      buf_size += sizeof (union kmem_bufctl) + sizeof (struct kmem_buftag);
      buf_size = P2ROUND (buf_size, align);
      cache->buf_size = buf_size;
    }

  kmem_cache_compute_properties (cache, flags);

#ifdef KMEM_USE_CPU_LAYER
  for (cache->cpu_pool_type = kmem_cpu_pool_types;
       buf_size <= cache->cpu_pool_type->buf_size;
       ++cache->cpu_pool_type);

  for (size_t i = 0; i < ARRAY_SIZE (cache->cpu_pools); i++)
    kmem_cpu_pool_init (&cache->cpu_pools[i], cache);
#endif

  ADAPTIVE_LOCK_GUARD (&kmem_cache_list_lock);
  list_insert_tail (&kmem_cache_list, &cache->node);
}

static inline int
kmem_cache_empty (struct kmem_cache *cache)
{
  return (cache->nr_objs == cache->nr_bufs);
}

static struct kmem_slab *
kmem_cache_buf_to_slab (const struct kmem_cache *cache, void *buf)
{
  if ((cache->flags & KMEM_CF_SLAB_EXTERNAL) ||
      cache->slab_size != PAGE_SIZE)
    return (NULL);

  return ((struct kmem_slab *)vm_page_end ((uintptr_t)buf) - 1);
}

static inline bool
kmem_cache_registration_required (const struct kmem_cache *cache)
{
  return ((cache->flags & KMEM_CF_SLAB_EXTERNAL) ||
          (cache->flags & KMEM_CF_VERIFY) ||
          cache->slab_size != PAGE_SIZE);
}

static void
kmem_cache_register (struct kmem_cache *cache, struct kmem_slab *slab)
{
  assert (kmem_cache_registration_required (cache));
  assert (!slab->nr_refs);

  bool virtual = kmem_pagealloc_is_virtual (cache->slab_size);

  for (uintptr_t va = kmem_slab_buf (slab), end = va + cache->slab_size;
       va < end; va += PAGE_SIZE)
    {
      phys_addr_t pa;

      if (virtual)
        {
          int error = pmap_kextract (va, &pa);
          assert (! error);
        }
      else
        pa = vm_page_direct_pa (va);

      _Auto page = vm_page_lookup (pa);
      assert (page);
      assert ((virtual && vm_page_type (page) == VM_PAGE_KERNEL) ||
              (!virtual && vm_page_type (page) == VM_PAGE_KMEM) );
      assert (!vm_page_get_priv (page));
      vm_page_set_priv (page, slab);
    }
}

static struct kmem_slab*
kmem_cache_lookup (struct kmem_cache *cache, void *buf)
{
  assert (kmem_cache_registration_required (cache));

  bool virtual = kmem_pagealloc_is_virtual (cache->slab_size);
  uintptr_t va = (uintptr_t) buf;
  phys_addr_t pa;

  if (virtual)
    {
      int error = pmap_kextract (va, &pa);

      if (error)
        return (NULL);
    }
  else
    pa = vm_page_direct_pa (va);

  _Auto page = vm_page_lookup (pa);

  if (! page)
    return (NULL);

  if ((virtual && (vm_page_type (page) != VM_PAGE_KERNEL)) ||
      (!virtual && (vm_page_type (page) != VM_PAGE_KMEM)))
    return (NULL);

  struct kmem_slab *slab = vm_page_get_priv (page);
  assert ((uintptr_t)buf >= kmem_slab_buf (slab));
  assert ((uintptr_t)buf < kmem_slab_buf (slab) + cache->slab_size);
  return (slab);
}

static int
kmem_cache_grow (struct kmem_cache *cache)
{
  adaptive_lock_acquire (&cache->lock);

  if (!kmem_cache_empty (cache))
    {
      adaptive_lock_release (&cache->lock);
      return (1);
    }

  size_t color = cache->color;
  cache->color += cache->align;

  if (cache->color > cache->color_max)
    cache->color = 0;

  adaptive_lock_release (&cache->lock);

  struct kmem_slab *slab = kmem_slab_create (cache, color);

  adaptive_lock_acquire (&cache->lock);

  if (slab)
    {
      list_insert_head (&cache->free_slabs, &slab->node);
      cache->nr_bufs += cache->bufs_per_slab;
      cache->nr_slabs++;
      cache->nr_free_slabs++;

      if (kmem_cache_registration_required (cache))
        kmem_cache_register (cache, slab);
    }

  /*
   * Even if our slab creation failed, another thread might have succeeded
   * in growing the cache.
   */
  int empty = kmem_cache_empty (cache);

  adaptive_lock_release (&cache->lock);
  return (!empty);
}

/*
 * Allocate a raw (unconstructed) buffer from the slab layer of a cache.
 *
 * The cache must be locked before calling this function.
 */
static void*
kmem_cache_alloc_from_slab (struct kmem_cache *cache)
{
  struct kmem_slab *slab;

  if (!list_empty (&cache->partial_slabs))
    slab = list_first_entry (&cache->partial_slabs, struct kmem_slab, node);
  else if (!list_empty (&cache->free_slabs))
    slab = list_first_entry (&cache->free_slabs, struct kmem_slab, node);
  else
    return (NULL);

  union kmem_bufctl *bufctl = slab->first_free;
  assert (bufctl);
  slab->first_free = bufctl->next;
  ++cache->nr_objs;

  if (++slab->nr_refs == cache->bufs_per_slab)
    { // The slab has become complete.
      list_remove (&slab->node);

      if (slab->nr_refs == 1)
        --cache->nr_free_slabs;
    }
  else if (slab->nr_refs == 1)
    {
      /*
       * The slab has become partial. Insert the new slab at the end of
       * the list to reduce fragmentation.
       */
      list_remove (&slab->node);
      list_insert_tail (&cache->partial_slabs, &slab->node);
      --cache->nr_free_slabs;
    }

  return (kmem_bufctl_to_buf (bufctl, cache));
}

/*
 * Release a buffer to the slab layer of a cache.
 *
 * The cache must be locked before calling this function.
 */
static void
kmem_cache_free_to_slab (struct kmem_cache *cache, void *buf)
{
  struct kmem_slab *slab = kmem_cache_buf_to_slab (cache, buf);
  if (! slab)
    {
      slab = kmem_cache_lookup (cache, buf);
      assert (slab);
    }

  assert (slab->nr_refs >= 1);
  assert (slab->nr_refs <= cache->bufs_per_slab);

  union kmem_bufctl *bufctl = kmem_buf_to_bufctl (buf, cache);
  bufctl->next = slab->first_free;
  slab->first_free = bufctl;
  --cache->nr_objs;

  if (--slab->nr_refs == 0)
    {
      /* The slab has become free - If it was partial,
       * remove it from its list */
      if (cache->bufs_per_slab != 1)
        list_remove (&slab->node);

      list_insert_head (&cache->free_slabs, &slab->node);
      ++cache->nr_free_slabs;
    }
  else if (slab->nr_refs == cache->bufs_per_slab - 1)
    // The slab has become partial.
    list_insert_head (&cache->partial_slabs, &slab->node);
}

static void
kmem_cache_alloc_verify (struct kmem_cache *cache, void *buf, int construct)
{

  struct kmem_buftag *buftag = kmem_buf_to_buftag (buf, cache);

  if (buftag->state != KMEM_BUFTAG_FREE)
    kmem_cache_error (cache, buf, KMEM_ERR_BUFTAG, buftag);

  void *addr = kmem_buf_verify_fill (buf, KMEM_FREE_PATTERN,
                                     KMEM_UNINIT_PATTERN, cache->bufctl_dist);

  if (addr)
    kmem_cache_error (cache, buf, KMEM_ERR_MODIFIED, addr);

  addr = (char *)buf + cache->obj_size;
  memset (addr, KMEM_REDZONE_BYTE, cache->redzone_pad);

  union kmem_bufctl *bufctl = kmem_buf_to_bufctl (buf, cache);
  bufctl->redzone = KMEM_REDZONE_WORD;
  buftag->state = KMEM_BUFTAG_ALLOC;

  if (construct && cache->ctor)
    cache->ctor (buf);
}

void*
kmem_cache_alloc (struct kmem_cache *cache)
{
#ifdef KMEM_USE_CPU_LAYER

  thread_pin ();
  struct kmem_cpu_pool *cpu_pool = kmem_cpu_pool_get (cache);
  adaptive_lock_acquire (&cpu_pool->lock);

fast_alloc:
  if (likely (cpu_pool->nr_objs > 0) )
    {
      void *buf = kmem_cpu_pool_pop (cpu_pool);
      bool verify = (cpu_pool->flags & KMEM_CF_VERIFY);
      adaptive_lock_release (&cpu_pool->lock);
      thread_unpin ();

      if (verify)
        kmem_cache_alloc_verify (cache, buf, KMEM_AV_CONSTRUCT);

      return (buf);
    }

  if (cpu_pool->array != NULL)
    {
      if (!kmem_cpu_pool_fill (cpu_pool, cache))
        {
          adaptive_lock_release (&cpu_pool->lock);
          thread_unpin ();

          if (!kmem_cache_grow (cache))
            return (NULL);

          thread_pin ();
          cpu_pool = kmem_cpu_pool_get (cache);
          adaptive_lock_acquire (&cpu_pool->lock);
        }

      goto fast_alloc;
    }

  adaptive_lock_release (&cpu_pool->lock);
  thread_unpin ();
#endif   // KMEM_USE_CPU_LAYER

slab_alloc:
  adaptive_lock_acquire (&cache->lock);
  void *buf = kmem_cache_alloc_from_slab (cache);
  adaptive_lock_release (&cache->lock);

  if (! buf)
    {
      if (!kmem_cache_grow (cache))
        return (NULL);

      goto slab_alloc;
    }

  if (cache->flags & KMEM_CF_VERIFY)
    kmem_cache_alloc_verify (cache, buf, KMEM_AV_NOCONSTRUCT);

  if (cache->ctor)
    cache->ctor (buf);

  return (buf);
}

static void
kmem_cache_free_verify (struct kmem_cache *cache, void *buf)
{
  struct kmem_slab *slab = kmem_cache_lookup (cache, buf);
  if (! slab)
    kmem_cache_error (cache, buf, KMEM_ERR_INVALID, NULL);

  uintptr_t slabend = P2ALIGN ((uintptr_t)slab->addr +
                               cache->slab_size, PAGE_SIZE);

  if ((uintptr_t) buf >= slabend)
    kmem_cache_error (cache, buf, KMEM_ERR_INVALID, NULL);

  if (((uintptr_t) buf - (uintptr_t)slab->addr) % cache->buf_size)
    kmem_cache_error (cache, buf, KMEM_ERR_INVALID, NULL);

  // As the buffer address is valid, accessing its buftag is safe.
  struct kmem_buftag *buftag = kmem_buf_to_buftag (buf, cache);
  if (buftag->state == KMEM_BUFTAG_ALLOC)
    ;
  else if (buftag->state == KMEM_BUFTAG_FREE)
    kmem_cache_error (cache, buf, KMEM_ERR_DOUBLEFREE, NULL);
  else
    kmem_cache_error (cache, buf, KMEM_ERR_BUFTAG, buftag);

  unsigned char *redzone_byte = (unsigned char *)buf + cache->obj_size;
  union kmem_bufctl *bufctl = kmem_buf_to_bufctl (buf, cache);

  for (; redzone_byte < (unsigned char *)bufctl; ++redzone_byte)
    if (*redzone_byte != KMEM_REDZONE_BYTE)
      kmem_cache_error (cache, buf, KMEM_ERR_REDZONE, redzone_byte);

  if (bufctl->redzone != KMEM_REDZONE_WORD)
    {
      uintptr_t word = KMEM_REDZONE_WORD;
      redzone_byte = kmem_buf_verify_bytes (&bufctl->redzone, &word,
                                            sizeof (bufctl->redzone));
      kmem_cache_error (cache, buf, KMEM_ERR_REDZONE, redzone_byte);
    }

  kmem_buf_fill (buf, KMEM_FREE_PATTERN, cache->bufctl_dist);
  buftag->state = KMEM_BUFTAG_FREE;
}

void
kmem_cache_free (struct kmem_cache *cache, void *obj)
{
#ifdef KMEM_USE_CPU_LAYER
  thread_pin ();
  struct kmem_cpu_pool *cpu_pool = kmem_cpu_pool_get (cache);

  if (cpu_pool->flags & KMEM_CF_VERIFY)
    {
      thread_unpin ();
      kmem_cache_free_verify (cache, obj);

      thread_pin ();
      cpu_pool = kmem_cpu_pool_get (cache);
    }

  adaptive_lock_acquire (&cpu_pool->lock);

fast_free:
  if (likely (cpu_pool->nr_objs < cpu_pool->size))
    {
      kmem_cpu_pool_push (cpu_pool, obj);
      adaptive_lock_release (&cpu_pool->lock);
      thread_unpin ();
      return;
    }

  if (cpu_pool->array)
    {
      kmem_cpu_pool_drain (cpu_pool, cache);
      goto fast_free;
    }

  adaptive_lock_release (&cpu_pool->lock);
  void **array = kmem_cache_alloc (cache->cpu_pool_type->array_cache);

  if (array)
    {
      adaptive_lock_acquire (&cpu_pool->lock);

      /*
       * Another thread may have built the CPU pool while the lock was
       * dropped.
       */
      if (cpu_pool->array)
        {
          adaptive_lock_release (&cpu_pool->lock);
          thread_unpin ();

          kmem_cache_free (cache->cpu_pool_type->array_cache, array);

          thread_pin ();
          cpu_pool = kmem_cpu_pool_get (cache);
          adaptive_lock_acquire (&cpu_pool->lock);
          goto fast_free;
        }

      kmem_cpu_pool_build (cpu_pool, cache, array);
      goto fast_free;
    }

  thread_unpin ();
#else
  if (cache->flags & KMEM_CF_VERIFY)
    kmem_cache_free_verify (cache, obj);
#endif // KMEM_USE_CPU_LAYER

  adaptive_lock_acquire (&cache->lock);
  kmem_cache_free_to_slab (cache, obj);
  adaptive_lock_release (&cache->lock);
}

void
kmem_cache_info (struct kmem_cache *cache, struct stream *stream)
{
  char flags_str[64];

  snprintf (flags_str, sizeof (flags_str), "%s%s",
            (cache->flags & KMEM_CF_SLAB_EXTERNAL) ? " SLAB_EXTERNAL" : "",
            (cache->flags & KMEM_CF_VERIFY) ? " VERIFY" : "");

  ADAPTIVE_LOCK_GUARD (&cache->lock);

  fmt_xprintf (stream, "kmem:         flags: 0x%x%s\n",
               cache->flags, flags_str);
  fmt_xprintf (stream, "kmem:      obj_size: %zu\n", cache->obj_size);
  fmt_xprintf (stream, "kmem:         align: %zu\n", cache->align);
  fmt_xprintf (stream, "kmem:      buf_size: %zu\n", cache->buf_size);
  fmt_xprintf (stream, "kmem:   bufctl_dist: %zu\n", cache->bufctl_dist);
  fmt_xprintf (stream, "kmem:     slab_size: %zu\n", cache->slab_size);
  fmt_xprintf (stream, "kmem:     color_max: %zu\n", cache->color_max);
  fmt_xprintf (stream, "kmem: bufs_per_slab: %zu\n", cache->bufs_per_slab);
  fmt_xprintf (stream, "kmem:       nr_objs: %zu\n", cache->nr_objs);
  fmt_xprintf (stream, "kmem:       nr_bufs: %zu\n", cache->nr_bufs);
  fmt_xprintf (stream, "kmem:      nr_slabs: %zu\n", cache->nr_slabs);
  fmt_xprintf (stream, "kmem: nr_free_slabs: %zu\n", cache->nr_free_slabs);
  fmt_xprintf (stream, "kmem:   buftag_dist: %zu\n", cache->buftag_dist);
  fmt_xprintf (stream, "kmem:   redzone_pad: %zu\n", cache->redzone_pad);

#ifdef KMEM_USE_CPU_LAYER
  fmt_xprintf (stream, "kmem: cpu_pool_size: %d\n",
               cache->cpu_pool_type->array_size);
#endif
}

#ifdef CONFIG_SHELL

static struct kmem_cache*
kmem_lookup_cache (const char *name)
{
  ADAPTIVE_LOCK_GUARD (&kmem_cache_list_lock);

  struct kmem_cache *cache;
  list_for_each_entry (&kmem_cache_list, cache, node)
    if (strcmp (cache->name, name) == 0)
      return (cache);

  return (NULL);
}

static void
kmem_shell_info (struct shell *shell, int argc, char **argv)
{
  (void)shell;

  if (argc < 2)
    kmem_info (shell->stream);
  else
    {
      struct kmem_cache *cache = kmem_lookup_cache (argv[1]);

      if (! cache)
        fmt_xprintf (shell->stream, "kmem: info: cache not found\n");
      else
        kmem_cache_info (cache, shell->stream);
    }
}

static struct shell_cmd kmem_shell_cmds[] =
{
  SHELL_CMD_INITIALIZER ("kmem_info", kmem_shell_info,
                         "kmem_info [<cache_name>]",
                         "display information about kernel memory and caches"),
};

static int __init
kmem_setup_shell (void)
{
  SHELL_REGISTER_CMDS (kmem_shell_cmds, shell_get_main_cmd_set ());
  return (0);
}

INIT_OP_DEFINE (kmem_setup_shell,
                INIT_OP_DEP (kmem_setup, true),
                INIT_OP_DEP (printf_setup, true),
                INIT_OP_DEP (shell_setup, true),
                INIT_OP_DEP (thread_setup, true));

#endif   // CONFIG_SHELL

#ifdef KMEM_USE_CPU_LAYER

static void
kmem_bootstrap_cpu (void)
{
  char name[KMEM_NAME_SIZE];

  for (size_t i = 0; i < ARRAY_SIZE (kmem_cpu_pool_types); i++)
    {
      struct kmem_cpu_pool_type *cpu_pool_type = &kmem_cpu_pool_types[i];
      cpu_pool_type->array_cache = &kmem_cpu_array_caches[i];
      sprintf (name, "kmem_cpu_array_%d", cpu_pool_type->array_size);
      size_t size = sizeof (void *) * cpu_pool_type->array_size;
      kmem_cache_init (cpu_pool_type->array_cache, name, size,
                       cpu_pool_type->array_align, NULL, 0);
    }
}
#endif   // KMEM_USE_CPU_LAYER

static int __init
kmem_bootstrap (void)
{
  // Make sure a bufctl can always be stored in a buffer.
  assert (sizeof (union kmem_bufctl) <= KMEM_ALIGN_MIN);

  list_init (&kmem_cache_list);
  adaptive_lock_init (&kmem_cache_list_lock);

#ifdef KMEM_USE_CPU_LAYER
  kmem_bootstrap_cpu ();
#endif   // KMEM_USE_CPU_LAYER

  // Prevent off slab data for the slab cache to avoid infinite recursion.
  kmem_cache_init (&kmem_slab_cache, "kmem_slab", sizeof (struct kmem_slab),
                   0, NULL, KMEM_CACHE_NOOFFSLAB);

  size_t size = 1 << KMEM_CACHES_FIRST_ORDER;
  char name[KMEM_NAME_SIZE];

  for (size_t i = 0; i < ARRAY_SIZE (kmem_caches); i++)
    {
      sprintf (name, "kmem_%zu", size);
      kmem_cache_init (&kmem_caches[i], name, size, 0, NULL, 0);
      size <<= 1;
    }

  return (0);
}

INIT_OP_DEFINE (kmem_bootstrap,
                INIT_OP_DEP (thread_bootstrap, true),
                INIT_OP_DEP (vm_page_setup, true));

static int __init
kmem_setup (void)
{
  return (0);
}

INIT_OP_DEFINE (kmem_setup,
                INIT_OP_DEP (kmem_bootstrap, true),
                INIT_OP_DEP (vm_kmem_setup, true) );

static inline size_t
kmem_get_index (size_t size)
{
  return (log2_order (size) - KMEM_CACHES_FIRST_ORDER);
}

static void
kmem_alloc_verify (struct kmem_cache *cache, void *buf, size_t size)
{
  assert (size <= cache->obj_size);
  memset ((char *)buf + size, KMEM_REDZONE_BYTE, cache->obj_size - size);
}

void *
kmem_alloc (size_t size)
{
  if (! size)
    return (NULL);

  size_t index = kmem_get_index (size);
  if (index < ARRAY_SIZE (kmem_caches))
    {
      struct kmem_cache *cache = &kmem_caches[index];
      void *buf = kmem_cache_alloc (cache);

      if (buf && (cache->flags & KMEM_CF_VERIFY))
        kmem_alloc_verify (cache, buf, size);

      return (buf);
    }

  return (kmem_pagealloc (size));
}

void*
kmem_zalloc (size_t size)
{
  void *ptr = kmem_alloc (size);
  if (! ptr)
    return (NULL);

  memset (ptr, 0, size);
  return (ptr);
}

static void
kmem_free_verify (struct kmem_cache *cache, void *buf, size_t size)
{
  assert (size <= cache->obj_size);

  unsigned char *redzone_byte = buf + size,
                *redzone_end = buf + cache->obj_size;

  for (; redzone_byte < redzone_end; ++redzone_byte)
    if (*redzone_byte != KMEM_REDZONE_BYTE)
      kmem_cache_error (cache, buf, KMEM_ERR_REDZONE, redzone_byte);
}

void
kmem_free (void *ptr, size_t size)
{
  if (!ptr || !size)
    return;

  size_t index = kmem_get_index (size);
  if (index < ARRAY_SIZE (kmem_caches))
    {
      struct kmem_cache *cache = &kmem_caches[index];

      if (cache->flags & KMEM_CF_VERIFY)
        kmem_free_verify (cache, ptr, size);

      kmem_cache_free (cache, ptr);
    }
  else
    kmem_pagefree (ptr, size);
}

void
kmem_info (struct stream *stream)
{
  size_t total = 0, total_physical = 0, total_virtual = 0, total_reclaim = 0,
         total_reclaim_physical = 0, total_reclaim_virtual = 0;

  fmt_xprintf (stream, "kmem: cache                  "
               "obj slab  bufs   objs   bufs    total reclaimable\n");
  fmt_xprintf (stream, "kmem: name                  size size /slab  "
               "usage  count   memory      memory\n");

  adaptive_lock_acquire (&kmem_cache_list_lock);

  struct kmem_cache *cache;
  list_for_each_entry (&kmem_cache_list, cache, node)
    {
      adaptive_lock_acquire (&cache->lock);

      size_t mem_usage = (cache->nr_slabs * cache->slab_size) >> 10,
             mem_reclaim = (cache->nr_free_slabs * cache->slab_size) >> 10;
      total += mem_usage;
      total_reclaim += mem_reclaim;

      if (kmem_pagealloc_is_virtual (cache->slab_size))
        {
          total_virtual += mem_usage;
          total_reclaim_virtual += mem_reclaim;
        }
      else
        {
          total_physical += mem_usage;
          total_reclaim_physical += mem_reclaim;
        }

      fmt_xprintf (stream,
                   "kmem: %-19s %6zu %3zuk  %4zu %6zu %6zu %7zuk %10zuk\n",
                   cache->name, cache->obj_size, cache->slab_size >> 10,
                   cache->bufs_per_slab, cache->nr_objs, cache->nr_bufs,
                   mem_usage, mem_reclaim);

      adaptive_lock_release (&cache->lock);
    }

  adaptive_lock_release (&kmem_cache_list_lock);
  fmt_xprintf (stream, "total: %zuk (phys: %zuk virt: %zuk), "
               "reclaim: %zuk (phys: %zuk virt: %zuk)\n",
               total, total_physical, total_virtual,
               total_reclaim, total_reclaim_physical, total_reclaim_virtual);
}
