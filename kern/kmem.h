/*
 * Copyright (c) 2010-2019 Richard Braun.
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
 * Object caching and general purpose memory allocator.
 */

#ifndef KERN_KMEM_H
#define KERN_KMEM_H

#include <stddef.h>

#include <kern/adaptive_lock.h>
#include <kern/init.h>
#include <kern/list.h>
#include <kern/stream.h>

#include <machine/cpu.h>

/*
 * Type for constructor functions.
 *
 * The pre-constructed state of an object is supposed to include only
 * elements such as e.g. linked lists, locks, reference counters. Therefore
 * constructors are expected to 1) never block, 2) never fail and 3) not
 * need any user-provided data. As a result, object construction never
 * performs dynamic resource allocation, which removes the need for
 * destructors.
 */
typedef void (*kmem_ctor_fn_t) (void *);

#if defined (CONFIG_SMP) && !defined (CONFIG_KMEM_NO_CPU_LAYER)
  #define KMEM_USE_CPU_LAYER
#endif

#ifdef KMEM_USE_CPU_LAYER

/*
 * Per-processor cache of pre-constructed objects.
 *
 * The flags member is a read-only CPU-local copy of the parent cache flags.
 */
struct kmem_cpu_pool
{
  __cacheline_aligned struct adaptive_lock lock;
  int flags;
  int size;
  int transfer_size;
  int nr_objs;
  void **array;
};

/*
 * When a cache is created, its CPU pool type is determined from the buffer
 * size. For small buffer sizes, many objects can be cached in a CPU pool.
 * Conversely, for large buffer sizes, this would incur much overhead, so only
 * a few objects are stored in a CPU pool.
 */
struct kmem_cpu_pool_type
{
  size_t buf_size;
  int array_size;
  size_t array_align;
  struct kmem_cache *array_cache;
};

#endif   // KMEM_USE_CPU_LAYER

// Cache name buffer size.
#define KMEM_NAME_SIZE   32

/*
 * Cache of objects.
 *
 * Locking order : cpu_pool -> cache. CPU pools locking is ordered by CPU ID.
 */
struct kmem_cache
{
#ifdef KMEM_USE_CPU_LAYER
  // CPU pool layer.
  struct kmem_cpu_pool cpu_pools[CONFIG_MAX_CPUS];
  struct kmem_cpu_pool_type *cpu_pool_type;
#endif

  // Slab layer.
  struct adaptive_lock lock;
  struct list node;     // Cache list linkage.
  struct list partial_slabs;
  struct list free_slabs;
  int flags;
  size_t obj_size;      // User-provided size.
  size_t align;
  size_t buf_size;      // Aligned object size.
  size_t bufctl_dist;   // Distance from buffer to bufctl.
  size_t slab_size;
  size_t color;
  size_t color_max;
  size_t bufs_per_slab;
  size_t nr_objs;       // Number of allocated objects.
  size_t nr_bufs;       // Total number of buffers.
  size_t nr_slabs;
  size_t nr_free_slabs;
  kmem_ctor_fn_t ctor;
  char name[KMEM_NAME_SIZE];
  size_t buftag_dist;   // Distance from buffer to buftag.
  size_t redzone_pad;   // Bytes from end of object to redzone word.
};

// Cache creation flags.
#define KMEM_CACHE_NOOFFSLAB    0x1   // Don't allocate external slab data.
#define KMEM_CACHE_PAGE_ONLY    0x2   // Allocate slabs from the page allocator.
#define KMEM_CACHE_VERIFY       0x4   // Use debugging facilities.

/*
 * Initialize a cache.
 *
 * Slabs may be allocated either from the page allocator or from kernel
 * virtual memory, unless KMEM_CACHE_PAGE_ONLY is set.
 */
void kmem_cache_init (struct kmem_cache *cache, const char *name,
                      size_t obj_size, size_t align, kmem_ctor_fn_t ctor,
                      int flags);

// Allocate an object from a cache.
void* kmem_cache_alloc (struct kmem_cache *cache);

// Release an object to its cache.
void kmem_cache_free (struct kmem_cache *cache, void *obj);

/*
 * Display internal cache information.
 *
 * If cache is NULL, this function displays all managed caches.
 */
void kmem_cache_info (struct kmem_cache *cache, struct stream *stream);

// Allocate size bytes of uninitialized memory.
void* kmem_alloc (size_t size);

// Allocate size bytes of zeroed memory.
void* kmem_zalloc (size_t size);

/*
 * Release memory obtained with kmem_alloc() or kmem_zalloc().
 *
 * The size argument must strictly match the value given at allocation time.
 */
void kmem_free (void *ptr, size_t size);

// Display global kernel memory information.
void kmem_info (struct stream *stream);

/*
 * This init operation provides :
 *  - allocation from caches backed by the page allocator
 */
INIT_OP_DECLARE (kmem_bootstrap);

/*
 * This init operation provides :
 *  - allocation from all caches
 */
INIT_OP_DECLARE (kmem_setup);

#endif
