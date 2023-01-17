/*
 * Copyright (c) 2011-2017 Richard Braun.
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
 * XXX This module is far from complete. It just provides the basic support
 * needed for kernel allocation.
 */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <kern/init.h>
#include <kern/kmem.h>
#include <kern/list.h>
#include <kern/log.h>
#include <kern/macros.h>
#include <kern/mutex.h>
#include <kern/panic.h>
#include <kern/percpu.h>
#include <kern/rbtree.h>
#include <kern/shell.h>
#include <kern/spinlock.h>
#include <kern/task.h>
#include <kern/unwind.h>

#include <machine/page.h>
#include <machine/pmap.h>

#include <vm/defs.h>
#include <vm/map.h>
#include <vm/kmem.h>
#include <vm/object.h>
#include <vm/page.h>

// Special threshold which disables the use of the free area cache address.
#define VM_MAP_NO_FIND_CACHE   (~(size_t)0)

// Maximum number of frames to allocate per mapping.
#define VM_MAP_MAX_FRAMES_ORDER   3
#define VM_MAP_MAX_FRAMES         (1 << VM_MAP_MAX_FRAMES_ORDER)

// Temporary virtual mappings used to retrieve pager data.

#define VM_MAP_CPU_MAX_VAS   3

struct vm_map_cpu_va
{
  struct mutex lock;
  uintptr_t vas[VM_MAP_CPU_MAX_VAS];
  uint32_t bitmap;
};

// How much to pagein when a fault occurs (expressed in bytes).
struct vm_map_page_target
{
  uint64_t front;
  uint64_t back;
};

static struct vm_map_cpu_va vm_map_cpu_vas __percpu;

/*
 * Mapping request.
 *
 * Most members are input parameters from a call to e.g. vm_map_enter(). The
 * start member is also an output argument. The next member is used internally
 * by the mapping functions.
 */
struct vm_map_request
{
  uintptr_t start;
  size_t size;
  size_t align;
  int flags;
  struct vm_object *object;
  uint64_t offset;
  struct vm_map_entry *next;
};

static int vm_map_prepare (struct vm_map *map, uintptr_t start,
                           size_t size, size_t align, int flags,
                           struct vm_object *object, uint64_t offset,
                           struct vm_map_request *request);

static int vm_map_insert (struct vm_map *map, struct vm_map_entry *entry,
                          const struct vm_map_request *request);

static struct kmem_cache vm_map_entry_cache;
static struct kmem_cache vm_map_cache;

struct vm_map vm_map_kernel_map;

static struct vm_map_entry*
vm_map_entry_create (void)
{
  return (kmem_cache_alloc (&vm_map_entry_cache));
}

static int
vm_map_entry_alloc (struct list *list, uint32_t n)
{
  list_init (list);
  for (uint32_t i = 0; i < n; ++i)
    {
      _Auto entry = vm_map_entry_create ();
      if (entry)
        {
          list_insert_tail (list, &entry->list_node);
          continue;
        }

      list_for_each_safe (list, nd, tmp)
        kmem_cache_free (&vm_map_entry_cache, nd);

      return (ENOMEM);
    }

  return (0);
}

static struct vm_map_entry*
vm_map_entry_pop (struct list *list)
{
  assert (!list_empty (list));
  _Auto ret = list_first_entry (list, struct vm_map_entry, list_node);
  list_remove (&ret->list_node);
  return (ret);
}

static void
vm_map_entry_free_obj (struct vm_map_entry *entry)
{
  struct vm_object *obj = entry->object;
  if (! obj)
    return;

  uint64_t offset = entry->offset;
  vm_object_remove (obj, offset, offset + entry->end - entry->start);
}

static void
vm_map_entry_destroy (struct vm_map_entry *entry)
{
  vm_map_entry_free_obj (entry);
  kmem_cache_free (&vm_map_entry_cache, entry);
}

static inline int
vm_map_entry_cmp_lookup (uintptr_t addr, const struct rbtree_node *node)
{
  _Auto entry = rbtree_entry (node, struct vm_map_entry, tree_node);
  return (addr >= entry->end ? 1 : (addr >= entry->start ? 0 : -1));
}

static inline int
vm_map_entry_cmp_insert (const struct rbtree_node *a,
                         const struct rbtree_node *b)
{
  _Auto entry = rbtree_entry (a, struct vm_map_entry, tree_node);
  return (vm_map_entry_cmp_lookup (entry->start, b));
}

static bool
vm_map_request_valid (const struct vm_map_request *request)
{
  return ((request->object || !request->offset) &&
          vm_page_aligned (request->offset) &&
          vm_page_aligned (request->start) &&
          request->size > 0 && vm_page_aligned (request->size) &&
          request->start + request->size > request->start &&
          (!request->align || request->align >= PAGE_SIZE) &&
          ISP2 (request->align) &&
          ((VM_MAP_PROT (request->flags) & VM_MAP_MAXPROT (request->flags)) ==
            VM_MAP_PROT (request->flags)) &&
          (!(request->flags & VM_MAP_FIXED) ||
            !request->align ||
            P2ALIGNED (request->start, request->align)));
}

/*
 * Look up an entry in a map.
 *
 * This function returns the entry which is closest to the given address
 * such that addr < entry->end (i.e. either containing or after the requested
 * address), or NULL if there is no such entry.
 */
static struct vm_map_entry*
vm_map_lookup_nearest (struct vm_map *map, uintptr_t addr)
{
  assert (vm_page_aligned (addr));
  _Auto entry = map->lookup_cache;

  if (entry && addr >= entry->start && addr < entry->end)
    return (entry);

  _Auto node = rbtree_lookup_nearest (&map->entry_tree, addr,
                                      vm_map_entry_cmp_lookup, RBTREE_RIGHT);
  if (node)
    {
      entry = rbtree_entry (node, struct vm_map_entry, tree_node);
      assert (addr < entry->end);
      map->lookup_cache = entry;
      return (entry);
    }

  return (NULL);
}

static void
vm_map_reset_find_cache (struct vm_map *map)
{
  map->find_cache = 0;
  map->find_cache_threshold = VM_MAP_NO_FIND_CACHE;
}

static int
vm_map_find_fixed (struct vm_map *map, struct vm_map_request *request)
{
  uintptr_t start = request->start;
  size_t size = request->size;

  if (start < map->start || start + size > map->end)
    return (ENOMEM);

  _Auto next = vm_map_lookup_nearest (map, start);
  if (! next)
    {
      if (map->end - start < size)
        return (ENOMEM);
    }
  else if (start >= next->start || next->start - start < size)
    return (ENOMEM);

  request->next = next;
  return (0);
}

static inline struct vm_map_entry*
vm_map_next (struct vm_map *map, struct vm_map_entry *entry)
{
  struct list *node = list_next (&entry->list_node);
  return (list_end (&map->entry_list, node) ?
          NULL : list_entry (node, struct vm_map_entry, list_node));
}

static int
vm_map_find_avail (struct vm_map *map, struct vm_map_request *request)
{
  // If there is a hint, try there.
  if (request->start &&
      vm_map_find_fixed (map, request) == 0)
    return (0);

  size_t size = request->size, align = request->align;
  uintptr_t base, start;

  if (size > map->find_cache_threshold)
    base = map->find_cache;
  else
    {
      base = map->start;

      /*
       * Searching from the map start means the area which size is the
       * threshold (or a smaller one) may be selected, making the threshold
       * invalid. Reset it.
       */
      map->find_cache_threshold = 0;
    }

retry:
  start = base;
  _Auto next = vm_map_lookup_nearest (map, start);

  while (1)
    {
      assert (start <= map->end);

      if (align)
        start = P2ROUND (start, align);

      /*
       * The end of the map has been reached, and no space could be found.
       * If the search didn't start at map->start, retry from there in case
       * space is available below the previous start address.
       */
      if (map->end - start < size)
        {
          if (base != map->start)
            {
              base = map->start;
              map->find_cache_threshold = 0;
              goto retry;
            }

          return (ENOMEM);
        }

      size_t space = !next ? map->end - start :
                     (start >= next->start ? 0 : next->start - start);

      if (space >= size)
        {
          map->find_cache = start + size;
          request->start = start;
          request->next = next;
          return (0);
        }

      if (space > map->find_cache_threshold)
        map->find_cache_threshold = space;

      start = next->end;
      next = vm_map_next (map, next);
    }
}

static void
vm_map_link (struct vm_map *map, struct vm_map_entry *entry,
             struct vm_map_entry *next)
{
  assert (entry->start < entry->end);

  if (! next)
    list_insert_tail (&map->entry_list, &entry->list_node);
  else
    list_insert_before (&entry->list_node, &next->list_node);

  rbtree_insert (&map->entry_tree, &entry->tree_node, vm_map_entry_cmp_insert);
  ++map->nr_entries;
}

static void
vm_map_unlink (struct vm_map *map, struct vm_map_entry *entry)
{
  assert (entry->start < entry->end);

  if (map->lookup_cache == entry)
    map->lookup_cache = NULL;

  list_remove (&entry->list_node);
  rbtree_remove (&map->entry_tree, &entry->tree_node);
  --map->nr_entries;
}

/*
 * Check mapping parameters, find a suitable area of virtual memory, and
 * prepare the mapping request for that region.
 */
static int
vm_map_prepare (struct vm_map *map, uintptr_t start,
                size_t size, size_t align, int flags,
                struct vm_object *object, uint64_t offset,
                struct vm_map_request *request)
{
  request->start = start;
  request->size = size;
  request->align = align;
  request->flags = flags;
  request->object = object;
  request->offset = offset;
  assert (vm_map_request_valid (request));
  return ((flags & VM_MAP_FIXED) ?
          vm_map_find_fixed (map, request) :
          vm_map_find_avail (map, request));
}

/*
 * Merging functions.
 *
 * There is room for optimization (e.g. not reinserting entries when it is
 * known the tree doesn't need to be adjusted), but focus on correctness for
 * now.
 */

static inline int
vm_map_try_merge_compatible (const struct vm_map_request *request,
                             const struct vm_map_entry *entry)
{
  return (request->object == entry->object &&
          ((request->flags & VM_MAP_ENTRY_MASK) ==
             (entry->flags & VM_MAP_ENTRY_MASK)));
}

static struct vm_map_entry*
vm_map_try_merge_prev (struct vm_map *map, const struct vm_map_request *request,
                       struct vm_map_entry *entry)
{
  assert (entry);

  if (!vm_map_try_merge_compatible (request, entry) ||
      entry->end != request->start)
    return (NULL);

  _Auto next = vm_map_next (map, entry);
  vm_map_unlink (map, entry);
  entry->end += request->size;
  vm_map_link (map, entry, next);
  return (entry);
}

static struct vm_map_entry*
vm_map_try_merge_next (struct vm_map *map, const struct vm_map_request *req,
                       struct vm_map_entry *entry)
{
  assert (entry);
  if (!vm_map_try_merge_compatible (req, entry))
    return (NULL);

  uintptr_t end = req->start + req->size;

  if (end != entry->start)
    return (NULL);

  _Auto next = vm_map_next (map, entry);
  vm_map_unlink (map, entry);
  entry->start = req->start;
  vm_map_link (map, entry, next);
  return (entry);
}

static struct vm_map_entry*
vm_map_try_merge_near (struct vm_map *map, const struct vm_map_request *request,
                       struct vm_map_entry *first, struct vm_map_entry *second)
{
  assert (first);
  assert (second);

  if (first->end == request->start &&
      request->start + request->size == second->start &&
      vm_map_try_merge_compatible (request, first) &&
      vm_map_try_merge_compatible (request, second))
    {
      _Auto next = vm_map_next (map, second);
      vm_map_unlink (map, first);
      vm_map_unlink (map, second);
      first->end = second->end;
      vm_map_entry_destroy (second);
      vm_map_link (map, first, next);
      return (first);
    }

  _Auto entry = vm_map_try_merge_prev (map, request, first);
  return (entry ?: vm_map_try_merge_next (map, request, second));
}

static struct vm_map_entry*
vm_map_try_merge (struct vm_map *map, const struct vm_map_request *request)
{
  // Statically allocated map entries must not be merged */
  assert (!(request->flags & VM_MAP_NOMERGE));

  if (!request->next)
    {
      struct list *node = list_last (&map->entry_list);

      if (list_end (&map->entry_list, node))
        return (NULL);

      _Auto prev = list_entry (node, struct vm_map_entry, list_node);
      return (vm_map_try_merge_prev (map, request, prev));
    }

  struct list *node = list_prev (&request->next->list_node);
  if (list_end (&map->entry_list, node))
    return (vm_map_try_merge_next (map, request, request->next));

  _Auto prev = list_entry (node, struct vm_map_entry, list_node);
  return (vm_map_try_merge_near (map, request, prev, request->next));
}

/*
 * Convert a prepared mapping request into an entry in the given map.
 *
 * If entry is NULL, a map entry is allocated for the mapping.
 */
static int
vm_map_insert (struct vm_map *map, struct vm_map_entry *entry,
               const struct vm_map_request *request)
{
  if (! entry)
    {
      entry = vm_map_try_merge (map, request);
      if (entry)
        goto out;

      entry = vm_map_entry_create ();
      if (! entry)
        return (ENOMEM);
    }

  entry->start = request->start;
  entry->end = request->start + request->size;
  entry->object = request->object;
  entry->offset = request->offset;
  entry->flags = request->flags & VM_MAP_ENTRY_MASK;
  vm_map_link (map, entry, request->next);

  if (entry->object)
    vm_object_ref (entry->object);

out:
  map->size += request->size;
  return (0);
}

int
vm_map_enter (struct vm_map *map, uintptr_t *startp,
              size_t size, size_t align, int flags,
              struct vm_object *object, uint64_t offset)
{
  SXLOCK_EXGUARD (&map->lock);
  struct vm_map_request request;
  int error = vm_map_prepare (map, *startp, size, align, flags, object,
                              offset, &request);

  if (error != 0 ||
      (error = vm_map_insert (map, NULL, &request)) != 0)
    {
      vm_map_reset_find_cache (map);
      return (error);
    }

  *startp = request.start;
  return (0);
}

static void
vm_map_entry_assign (struct vm_map_entry *dst, const struct vm_map_entry *src)
{
  *dst = *src;
  if (dst->object)
    vm_object_ref (dst->object);
}

static void
vm_map_split_entries (struct vm_map_entry *prev, struct vm_map_entry *next,
                      uintptr_t split_addr)
{
  uintptr_t delta = split_addr - prev->start;
  prev->end = split_addr;
  next->start = split_addr;

  if (next->object)
    next->offset += delta;
}

static void
vm_map_clip_start (struct vm_map *map, struct vm_map_entry *entry,
                   uintptr_t start, struct list *alloc)
{
  if (start <= entry->start || start >= entry->end)
    return;

  _Auto new_entry = vm_map_entry_pop (alloc);
  _Auto next = vm_map_next (map, entry);
  vm_map_unlink (map, entry);

  vm_map_entry_assign (new_entry, entry);
  vm_map_split_entries (new_entry, entry, start);
  vm_map_link (map, entry, next);
  vm_map_link (map, new_entry, entry);
}

static void
vm_map_clip_end (struct vm_map *map, struct vm_map_entry *entry,
                 uintptr_t end, struct list *alloc)
{
  if (end <= entry->start || end >= entry->end)
    return;

  _Auto new_entry = vm_map_entry_pop (alloc);
  _Auto next = vm_map_next (map, entry);
  vm_map_unlink (map, entry);

  vm_map_entry_assign (new_entry, entry);
  vm_map_split_entries (entry, new_entry, end);
  vm_map_link (map, entry, next);
  vm_map_link (map, new_entry, next);
}

static int
vm_map_remove_impl (struct vm_map *map, uintptr_t start,
                    uintptr_t end, struct list *list)
{
  assert (start >= map->start);
  assert (end <= map->end);
  assert (start < end);

  SXLOCK_EXGUARD (&map->lock);
  _Auto entry = vm_map_lookup_nearest (map, start);
  if (! entry)
    return (0);

  // Pre-allocate the VM map entries.
  uint32_t n_entries = start > entry->start && start < entry->end,
           n_loops = 0;
  for (_Auto tmp = entry; tmp->start < end; )
    {
      if (end > tmp->start && end < tmp->end)
        ++n_entries;

      ++n_loops;
      struct list *nx = list_next (&tmp->list_node);
      if (list_end (&map->entry_list, nx))
        break;

      tmp = list_entry (nx, struct vm_map_entry, list_node);
    }

  struct list alloc_entries;
  int error = vm_map_entry_alloc (&alloc_entries, n_entries);

  if (error)
    return (error);

  vm_map_clip_start (map, entry, start, &alloc_entries);
  for (uint32_t i = 0; i < n_loops; ++i)
    {
      vm_map_clip_end (map, entry, end, &alloc_entries);
      map->size -= entry->end - entry->start;
      struct list *node = list_next (&entry->list_node);
      vm_map_unlink (map, entry);

      list_insert_tail (list, &entry->list_node);
      entry = list_entry (node, struct vm_map_entry, list_node);
    }

  assert (list_empty (&alloc_entries));
  vm_map_reset_find_cache (map);
  return (0);
}

int
vm_map_remove (struct vm_map *map, uintptr_t start, uintptr_t end)
{
  struct list entries;
  list_init (&entries);

  int error = vm_map_remove_impl (map, start, end, &entries);
  if (! error)
    list_for_each_safe (&entries, ex, tmp)
      vm_map_entry_destroy (list_entry (ex, struct vm_map_entry, list_node));

  return (error);
}

static void
vm_map_init (struct vm_map *map, struct pmap *pmap,
             uintptr_t start, uintptr_t end)
{
  assert (vm_page_aligned (start));
  assert (vm_page_aligned (end));
  assert (start < end);

  sxlock_init (&map->lock);
  list_init (&map->entry_list);
  rbtree_init (&map->entry_tree);
  map->nr_entries = 0;
  map->start = start;
  map->end = end;
  map->size = 0;
  map->lookup_cache = NULL;
  vm_map_reset_find_cache (map);
  map->pmap = pmap;
  map->soft_faults = 0;
  map->hard_faults = 0;
}

#ifdef CONFIG_SHELL

static void
vm_map_shell_info (struct shell *shell, int argc, char **argv)
{
  if (argc < 2)
    {
      stream_puts (shell->stream, "usage: vm_map_info task\n");
      return;
    }
  
  const _Auto task = task_lookup (argv[1]);
  if (! task)
    stream_puts (shell->stream, "vm_map_info: task not found\n");
  else
    vm_map_info (task_get_vm_map (task), shell->stream);
}

static struct shell_cmd vm_map_shell_cmds[] =
{
  SHELL_CMD_INITIALIZER ("vm_map_info", vm_map_shell_info,
                         "vm_map_info <task_name>",
                         "display information about a VM map"),
};

static int __init
vm_map_setup_shell (void)
{
  SHELL_REGISTER_CMDS (vm_map_shell_cmds, shell_get_main_cmd_set ());
  return (0);
}

INIT_OP_DEFINE (vm_map_setup_shell,
                INIT_OP_DEP (printf_setup, true),
                INIT_OP_DEP (shell_setup, true),
                INIT_OP_DEP (task_setup, true),
                INIT_OP_DEP (vm_map_setup, true));

#endif

static int __init
vm_map_bootstrap (void)
{
  vm_map_init (vm_map_get_kernel_map (), pmap_get_kernel_pmap (),
               PMAP_START_KMEM_ADDRESS, PMAP_END_KMEM_ADDRESS);
  kmem_cache_init (&vm_map_entry_cache, "vm_map_entry",
                   sizeof (struct vm_map_entry), 0, NULL,
                   KMEM_CACHE_PAGE_ONLY);
  return (0);
}

INIT_OP_DEFINE (vm_map_bootstrap,
                INIT_OP_DEP (mutex_setup, true),
                INIT_OP_DEP (kmem_bootstrap, true),
                INIT_OP_DEP (thread_bootstrap, true));

// Paging cluster parameters (Expressed in bytes).
static const struct vm_map_page_target vm_map_page_targets[] =
{
  [VM_ADV_NORMAL]     = { .front = PAGE_SIZE, .back = 3 * PAGE_SIZE },
  [VM_ADV_RANDOM]     = { .front = 0, .back = 0 },
  [VM_ADV_SEQUENTIAL] = { .front = 0, .back = 8 * PAGE_SIZE }
};

static uintptr_t vm_map_ipc_va;

static int __init
vm_map_setup (void)
{
  kmem_cache_init (&vm_map_cache, "vm_map", sizeof (struct vm_map),
                   0, NULL, KMEM_CACHE_PAGE_ONLY);

  /*
   * The total size is computed as such:
   * - One page for IPC operations (mapped by a special PTE in the pmap module)
   * - One virtual mapping per CPU, which includes the maximum number of frames
   *   needed to pagein data times the maximum number of mappings per cpu.
   */
  size_t size = PAGE_SIZE + cpu_count () * PAGE_SIZE *
                VM_MAP_MAX_FRAMES * VM_MAP_CPU_MAX_VAS;
  if (vm_map_enter (&vm_map_kernel_map, &vm_map_ipc_va, size,
                    0, VM_MAP_FLAGS (VM_PROT_RDWR, VM_PROT_RDWR,
                                     VM_INHERIT_NONE, VM_ADV_DEFAULT, 0),
                    NULL, 0) != 0)
    panic ("could not create internal mappings");

  uintptr_t va = vm_map_ipc_va + PAGE_SIZE;
  for (uint32_t i = 0; i < cpu_count (); ++i)
    {
      _Auto vp = percpu_ptr (vm_map_cpu_vas, i);
      mutex_init (&vp->lock);
      vp->bitmap = (1 << VM_MAP_CPU_MAX_VAS) - 1;
      for (uint32_t j = 0; j < ARRAY_SIZE (vp->vas); ++j, va += PAGE_SIZE)
        vp->vas[j] = va;
    }

  return (0);
}

uintptr_t
vm_map_ipc_addr (void)
{
  return (vm_map_ipc_va);
}

static uintptr_t
vm_map_get_pagein_addr (void)
{
  CPU_INTR_GUARD ();
  _Auto vp = cpu_local_ptr (vm_map_cpu_vas);

  if (!vp->bitmap)
    mutex_lock (&vp->lock);

  assert (vp->bitmap);
  int idx = __builtin_ffs (vp->bitmap) - 1;

  uintptr_t ret = vp->vas[idx];
  vp->vas[idx] = 0;
  vp->bitmap &= ~(1 << idx);

  if (!vp->bitmap)
    mutex_lock (&vp->lock);

  assert (vm_page_aligned (ret));
  return (ret);
}

static void
vm_map_put_pagein_addr (struct pmap *pmap, uintptr_t va, int n)
{
  cpu_flags_t flags;
  cpu_intr_save (&flags);

  _Auto vp = cpu_local_ptr (vm_map_cpu_vas);
  assert (vp->bitmap != (1 << VM_MAP_CPU_MAX_VAS) - 1);

  int idx = __builtin_ctz (~vp->bitmap);
  assert (vp->vas[idx] == 0);
  vp->vas[idx] = va;

  uint32_t prev = vp->bitmap;
  vp->bitmap |= 1 << idx;

  cpu_intr_restore (flags);
  if (! prev)
    mutex_unlock (&vp->lock);

  for (int i = 0; i < n; ++i, va += PAGE_SIZE)
    pmap_remove (pmap, va, NULL);
}

INIT_OP_DEFINE (vm_map_setup,
                INIT_OP_DEP (pmap_setup, true),
                INIT_OP_DEP (printf_setup, true),
                INIT_OP_DEP (vm_map_bootstrap, true));

static int
vm_map_alloc_fault_pages (struct vm_map_entry *entry, struct vm_page **frames,
                          uint64_t offset, uintptr_t addr, uint64_t *startp)
{
  size_t adv = VM_MAP_ADVICE (entry->flags);
  assert (adv < ARRAY_SIZE (vm_map_page_targets));
  _Auto target = &vm_map_page_targets[adv];

  // Mind overflows when computing the offsets.
  *startp = MIN (addr - entry->start, target->front);
  uint64_t last_off = MIN (entry->end - addr, target->back);
  uint32_t order = (uint32_t)(log2 ((last_off + *startp) >> PAGE_SHIFT));

  *startp = offset - *startp;
  return (vm_page_array_alloc (frames, order,
                               VM_PAGE_SEL_HIGHMEM, VM_PAGE_OBJECT));
}

static inline void
vm_map_cleanup_object (void *ptr)
{
  vm_object_unref (*(struct vm_object **)ptr);
}

static int
vm_map_fault_get_data (struct vm_map *map, struct vm_object *object,
                       uint64_t offset, struct vm_page **frames,
                       int prot, int nr_pages)
{
  THREAD_PIN_GUARD ();
  uintptr_t va = vm_map_get_pagein_addr ();

  for (int i = 0; i < nr_pages; ++i)
    {
      int error = pmap_enter (map->pmap, va + i * PAGE_SIZE,
                              vm_page_to_pa (frames[i]),
                              VM_PROT_RDWR, PMAP_NO_CHECK);
      if (unlikely (error))
        {
          vm_map_put_pagein_addr (map->pmap, va, i);
          return (-EINTR);
        }
    }

  int ret = pmap_update (map->pmap) != 0 ? -EINTR :
            vm_object_pager_get (object, offset,
                                 nr_pages * PAGE_SIZE, prot, (void *)va);

  vm_map_put_pagein_addr (map->pmap, va, nr_pages);
  return (ret);
}

int
vm_map_fault (struct vm_map *map, uintptr_t addr, int prot, int flags)
{
  assert (map != vm_map_get_kernel_map ());
  addr = vm_page_trunc (addr);

  struct vm_map_entry *entry, tmp;
  struct vm_object *object;
  uint64_t offset;

  // TODO: Handle COW pages.
retry:

  {
    SXLOCK_SHGUARD (&map->lock);
    entry = vm_map_lookup_nearest (map, addr);

    if (!entry || addr < entry->start)
      return (EFAULT);
    else if ((prot & VM_MAP_PROT (entry->flags)) != prot)
      return (EACCES);

    prot = VM_MAP_PROT (entry->flags);
    object = entry->object;
    assert (object);   // Null vm-objects are kernel-only and always wired.

    offset = entry->offset + (addr - entry->start);
    struct vm_page *page = vm_object_lookup (object, offset);

    if (page)
      {
        if (pmap_enter (map->pmap, addr, vm_page_to_pa (page),
                        prot, 0) == 0)
          pmap_update (map->pmap);

        vm_page_unref (page);
        atomic_add_rlx (&map->soft_faults, 1);
        return (0);
      }

    // Prevent the VM object from going away as we drop the lock.
    vm_map_entry_assign (&tmp, entry);
    entry = &tmp;
  }

  if (flags & VM_MAP_FAULT_INTR)
    cpu_intr_enable ();

  CLEANUP (vm_map_cleanup_object) __unused _Auto objg = object;
  struct vm_page *frames[VM_MAP_MAX_FRAMES];
  uint64_t start_off;
  int n_pages = vm_map_alloc_fault_pages (entry, frames, offset,
                                          addr, &start_off);

  if (n_pages < 0)
    { // Allocation was interrupted. Let userspace handle things.
      if (flags & VM_MAP_FAULT_INTR)
        cpu_intr_disable ();

      return (0);
    }

  n_pages = vm_map_fault_get_data (map, object, offset, frames,
                                     prot, 1 << n_pages);

  if (flags & VM_MAP_FAULT_INTR)
    cpu_intr_disable ();

  if (n_pages < 0)
    return (n_pages == -EINTR ? 0 : -n_pages);
  else if (start_off + n_pages * PAGE_SIZE < offset)
    /* We didn't cover the faulting page. This is probably due to a truncated
     * object. Return an error that maps to SIGBUS. */
    return (EIO);

  SXLOCK_EXGUARD (&map->lock);
  _Auto e2 = vm_map_lookup_nearest (map, addr);

  if (!(e2 && e2->object == entry->object &&
        addr >= e2->start &&
        addr - (uintptr_t)(offset - start_off) + n_pages * PAGE_SIZE <= e2->end))
    {
      vm_page_array_free (frames, log2 (n_pages));
      goto retry;
    }

  prot = VM_MAP_PROT (e2->flags);
  addr -= offset - start_off;

  for (uint32_t i = 0; i < (uint32_t)n_pages; ++i)
    {
      struct vm_page *page = frames[i];
      if (vm_object_insert (object, page, offset + i * PAGE_SIZE) != 0 ||
          pmap_enter (map->pmap, addr + i * PAGE_SIZE,
                      vm_page_to_pa (page), prot, PMAP_PEF_GLOBAL) != 0)
        {
          vm_page_array_free (&frames[i], n_pages - i);
          break;
        }
    }

  pmap_update (map->pmap);
  atomic_add_rlx (&map->hard_faults, 1);
  return (0);
}

int
vm_map_create (struct vm_map **mapp)
{
  struct vm_map *map = kmem_cache_alloc (&vm_map_cache);
  if (! map)
    return (ENOMEM);

  struct pmap *pmap;
  int error = pmap_copy (pmap_get_kernel_pmap (), &pmap);

  if (error)
    {
      kmem_cache_free (&vm_map_cache, map);
      return (error);
    }

  vm_map_init (map, pmap, PMAP_START_ADDRESS, PMAP_END_ADDRESS);
  *mapp = map;
  return (0);
}

int
vm_map_lookup (struct vm_map *map, uintptr_t addr,
               struct vm_map_entry *entry)
{
  SXLOCK_SHGUARD (&map->lock);
  _Auto ep = vm_map_lookup_nearest (map, addr);

  if (! ep)
    return (ESRCH);

  vm_map_entry_assign (entry, ep);
  return (0);
}

int
vm_copy (void *dst, const void *src, size_t size)
{
  struct unw_fixup fixup;
  int res = unw_fixup_save (&fixup);

  if (res == 0)
    memcpy (dst, src, size);

  return (res);
}

static void
vm_map_destroy_impl (struct vm_map *map)
{
  SXLOCK_EXGUARD (&map->lock);
  rbtree_for_each_remove (&map->entry_tree, entry, tmp)
    vm_map_entry_destroy (rbtree_entry (entry, struct vm_map_entry,
                                        tree_node));
}

void
vm_map_destroy (struct vm_map *map)
{
  vm_map_destroy_impl (map);
  kmem_cache_free (&vm_map_cache, map);
}

void
vm_map_info (struct vm_map *map, struct stream *stream)
{
  const char *name = map == vm_map_get_kernel_map () ? "kernel map" : "map";
  SXLOCK_SHGUARD (&map->lock);

  fmt_xprintf (stream, "vm_map: %s: %016lx-%016lx\n",
               name, map->start, map->end);
  fmt_xprintf (stream, "vm_map:      start             end          "
               "size     offset   flags    type\n");

  struct vm_map_entry *entry;
  list_for_each_entry (&map->entry_list, entry, list_node)
    {
      const char *type = entry->object ? "object" : "null";
      fmt_xprintf (stream, "vm_map: %016lx %016lx %8luk %08llx %08x %s\n",
                   entry->start, entry->end,
                   (entry->end - entry->start) >> 10,
                   entry->offset, entry->flags, type);
    }

  fmt_xprintf (stream, "vm_map: total: %zuk\n", map->size >> 10);
}
