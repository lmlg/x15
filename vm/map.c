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
 */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <kern/init.h>
#include <kern/ipc.h>
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

// Maximum number of frames to allocate when faulting in pages.
#define VM_MAP_MAX_FRAMES_ORDER   3
#define VM_MAP_MAX_FRAMES         (1 << VM_MAP_MAX_FRAMES_ORDER)

struct vm_map_page_target
{
  uintptr_t front;
  uintptr_t back;
};

struct vm_map_fork_buf
{
  struct vm_page *page;
  int prot;
};

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
  int flags;
  struct vm_object *object;
  uint64_t offset;
  struct vm_map_entry *next;
};

static int vm_map_prepare (struct vm_map *map, uintptr_t start, size_t size,
                           int flags, struct vm_object *object,
                           uint64_t offset, struct vm_map_request *request);

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
      if (! entry)
        {
          list_for_each_safe (list, nd, tmp)
            kmem_cache_free (&vm_map_entry_cache,
                             structof (nd, struct vm_map_entry, list_node));

          return (ENOMEM);
        }

      list_insert_tail (list, &entry->list_node);
    }

  return (0);
}

static struct vm_map_entry*
vm_map_entry_pop (struct list *list)
{
  assert (!list_empty (list));
  return (list_pop (list, struct vm_map_entry, list_node));
}

static void
vm_map_entry_free_obj (struct vm_map_entry *entry, bool clear)
{
  struct vm_object *obj = entry->object;
  if (! obj)
    return;
  else if (clear)
    {
      uint64_t off = entry->offset;
      vm_object_remove (obj, off, off + entry->end - entry->start);
    }

  vm_object_unref (obj);
}

static void
vm_map_entry_destroy (struct vm_map_entry *entry, bool clear)
{
  vm_map_entry_free_obj (entry, clear);
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
          ((VM_MAP_PROT (request->flags) & VM_MAP_MAXPROT (request->flags)) ==
            VM_MAP_PROT (request->flags)));
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
      _Auto e2 = rbtree_entry (node, struct vm_map_entry, tree_node);
      assert (addr < e2->end);
      atomic_cas_rlx (&map->lookup_cache, entry, e2);
      return (e2);
    }

  return (NULL);
}

static int
vm_map_find_fixed (struct vm_map *map, struct vm_map_request *request)
{
  uintptr_t start = request->start;
  size_t size = request->size;

  if (start < map->start || start + size > map->end)
    return (ENOMEM);

  _Auto next = vm_map_lookup_nearest (map, start);
  if (next && (start >= next->start || next->start - start < size))
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

  size_t size = request->size;
  uintptr_t start = map->start;
  _Auto next = vm_map_lookup_nearest (map, start);

  while (1)
    {
      assert (start <= map->end);

      if (map->end - start < size)
        // The end of the map has been reached and no space could be found.
        return (ENOMEM);

      size_t space = !next ? map->end - start :
                     (start >= next->start ? 0 : next->start - start);

      if (space >= size)
        {
          request->start = start;
          request->next = next;
          return (0);
        }

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

  // No need for atomics here as this is done under an exclusive lock.
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
                size_t size, int flags, struct vm_object *object,
                uint64_t offset, struct vm_map_request *request)
{
  request->start = start;
  request->size = size;
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
      entry->end != request->start ||
      (entry->object &&
       entry->offset + entry->end - entry->start != request->offset))
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

  if (end != entry->start ||
      (entry->object &&
       req->offset + req->size != entry->offset))
    return (NULL);

  _Auto next = vm_map_next (map, entry);
  vm_map_unlink (map, entry);
  entry->start = req->start;
  entry->offset = req->offset;
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
      vm_map_try_merge_compatible (request, second) &&
      (!first->object ||
       (first->offset + first->end - first->start == request->offset &&
        request->offset + request->size == second->offset)))
    {
      _Auto next = vm_map_next (map, second);
      vm_map_unlink (map, first);
      vm_map_unlink (map, second);
      first->end = second->end;
      vm_map_entry_destroy (second, false);
      vm_map_link (map, first, next);
      return (first);
    }

  _Auto entry = vm_map_try_merge_prev (map, request, first);
  return (entry ?: vm_map_try_merge_next (map, request, second));
}

static struct vm_map_entry*
vm_map_try_merge (struct vm_map *map, const struct vm_map_request *request)
{
  // Statically allocated map entries must not be merged.
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
  entry->offset = (request->flags & VM_MAP_ANON) ?
    (uint64_t)request->start : request->offset;
  entry->flags = request->flags & VM_MAP_ENTRY_MASK;
  vm_map_link (map, entry, request->next);

  if (entry->object)
    vm_object_ref (entry->object);

out:
  map->size += request->size;
  return (0);
}

static inline int
vm_map_enter_locked (struct vm_map *map, uintptr_t *startp, size_t size,
                     int flags, struct vm_object *object, uint64_t offset)
{
  struct vm_map_request request;
  int error = vm_map_prepare (map, *startp, size, flags, object,
                              offset, &request);

  if (error != 0 ||
      (error = vm_map_insert (map, NULL, &request)) != 0)
    return (error);

  *startp = request.start;
  return (0);
}

int
vm_map_enter (struct vm_map *map, uintptr_t *startp, size_t size,
              int flags, struct vm_object *object, uint64_t offset)
{
  SXLOCK_EXGUARD (&map->lock);
  return (vm_map_enter_locked (map, startp, size, flags, object, offset));
}

static void
vm_map_entry_copy_impl (struct vm_map_entry *dst,
                        const struct vm_map_entry *src)
{
  dst->start = src->start;
  dst->end = src->end;
  dst->offset = src->offset;
  dst->flags = src->flags;
}

static void
vm_map_entry_copy (struct vm_map_entry *dst, const struct vm_map_entry *src)
{
  vm_map_entry_copy_impl (dst, src);
  dst->object = src->object;
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

  vm_map_entry_copy (new_entry, entry);
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

  vm_map_entry_copy (new_entry, entry);
  vm_map_split_entries (entry, new_entry, end);
  vm_map_link (map, entry, next);
  vm_map_link (map, new_entry, next);
}

static int
vm_map_remove_impl (struct vm_map *map, uintptr_t start,
                    uintptr_t end, struct list *list, bool clear)
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

  if (clear)
    { // Don't prevent lookups and page faults from here on.
      sxlock_share (&map->lock);
      pmap_remove_range (map->pmap, start, end,
                         PMAP_PEF_GLOBAL | PMAP_IGNORE_ERRORS);
      pmap_update (map->pmap);
    }

  return (0);
}

int
vm_map_remove (struct vm_map *map, uintptr_t start, uintptr_t end)
{
  struct list entries;
  list_init (&entries);

  int error = vm_map_remove_impl (map, start, end, &entries, true);
  if (! error)
    list_for_each_safe (&entries, ex, tmp)
      vm_map_entry_destroy (list_entry (ex, struct vm_map_entry,
                                        list_node), true);

  return (error);
}

static void
vm_map_try_merge_entries (struct vm_map *map, struct vm_map_entry *prev,
                          struct vm_map_entry *next, struct list *dead)
{
  if ((prev->flags & VM_MAP_ENTRY_MASK) !=
      (next->flags & VM_MAP_ENTRY_MASK) ||
      prev->end != next->start ||
      prev->object != next->object ||
      prev->offset + prev->end - prev->start != next->offset)
    return;

  _Auto new_next = vm_map_next (map, next);

  next->start = prev->start;
  next->offset = prev->offset;
  vm_map_unlink (map, prev);
  vm_map_unlink (map, next);
  vm_map_link (map, next, new_next);
  list_insert_tail (dead, &prev->list_node);
}

#define VM_MAP_PROT_PFLAGS   (PMAP_PEF_GLOBAL | PMAP_IGNORE_ERRORS)

static int
vm_map_protect_entry (struct vm_map *map, struct vm_map_entry *entry,
                      uintptr_t start, uintptr_t end,
                      int prot, struct list *dead)
{
  if ((VM_MAP_MAXPROT (entry->flags) & prot) != prot)
    return (EACCES);
  else if (VM_MAP_PROT (entry->flags) == prot)
    return (0);   // Nothing to do.

  int nr_entries = (start != entry->start) + (end != entry->end);
  if (nr_entries != 0)
    {
      struct list entries;
      int error = vm_map_entry_alloc (&entries, nr_entries);
      if (error)
        return (error);

      vm_map_clip_start (map, entry, start, &entries);
      vm_map_clip_end (map, entry, end, &entries);
      VM_MAP_SET_PROT (&entry->flags, prot);
      assert (list_empty (&entries));
    }
  else
    {
      VM_MAP_SET_PROT (&entry->flags, prot);
      if (&entry->list_node != list_first (&map->entry_list))
        vm_map_try_merge_entries (map, list_prev_entry (entry, list_node),
                                  entry, dead);
    }

  if (prot == VM_PROT_NONE &&
      (VM_MAP_PROT (entry->flags) & VM_PROT_WRITE) == 0)
    pmap_remove_range (map->pmap, start, end, VM_MAP_PROT_PFLAGS);
  else
    pmap_protect_range (map->pmap, start, end, prot, VM_MAP_PROT_PFLAGS);

  return (0);
}

static int
vm_map_protect_impl (struct vm_map *map, uintptr_t start, uintptr_t end,
                     int prot, struct list *dead)
{
  SXLOCK_EXGUARD (&map->lock);
  _Auto entry = vm_map_lookup_nearest (map, start);
  if (! entry)
    return (ENOMEM);

  int error;
  struct vm_map_entry *next;

  while (1)
    {
      next = vm_map_next (map, entry);
      error = vm_map_protect_entry (map, entry, start, end, prot, dead);

      if (error || entry->end >= end)
        break;
      else if (!next || entry->end != next->start)
        {
          error = ENOMEM;
          break;
        }

      entry = next;
    }

  if (!error && next)
    vm_map_try_merge_entries (map, entry, next, dead);

  // Don't prevent lookups and page faults from here on.
  sxlock_share (&map->lock);
  pmap_update (map->pmap);
  return (error);
}

int
vm_map_protect (struct vm_map *map, uintptr_t start, uintptr_t end, int prot)
{
  if (!vm_page_aligned (start) || !vm_page_aligned (end) || end < start)
    return (EINVAL);

  struct list dead;
  list_init (&dead);
  int error = vm_map_protect_impl (map, start, end, prot, &dead);

  list_for_each_safe (&dead, nd, tmp)
    vm_map_entry_destroy (list_entry (nd, struct vm_map_entry,
                                      list_node), false);

  return (error);
}

static void
vm_map_init (struct vm_map *map, struct pmap *pmap,
             uintptr_t start, uintptr_t end, struct vm_object *priv)
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
  map->pmap = pmap;
  map->priv_cache = priv;
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
    {
      vm_map_info (task_get_vm_map (task), shell->stream);
      task_unref (task);
    }
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
               PMAP_START_KMEM_ADDRESS, PMAP_END_KMEM_ADDRESS, NULL);
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
  [VM_ADV_RANDOM]     = { .front = 0, .back = PAGE_SIZE },
  [VM_ADV_SEQUENTIAL] = { .front = 0, .back = 8 * PAGE_SIZE }
};

static uintptr_t vm_map_ipc_va;

static int __init
vm_map_setup (void)
{
  kmem_cache_init (&vm_map_cache, "vm_map", sizeof (struct vm_map),
                   0, NULL, KMEM_CACHE_PAGE_ONLY);

  // Allocate a page for IPC mapping purposes.
  if (vm_map_enter (&vm_map_kernel_map, &vm_map_ipc_va, PAGE_SIZE * 2,
                    VM_MAP_FLAGS (VM_PROT_RDWR, VM_PROT_RDWR,
                                  VM_INHERIT_NONE, VM_ADV_DEFAULT, 0),
                    NULL, 0) != 0)
    panic ("vm-map: could not create internal IPC mapping");

  return (0);
}

uintptr_t
vm_map_ipc_addr (void)
{
  return (vm_map_ipc_va);
}

INIT_OP_DEFINE (vm_map_setup,
                INIT_OP_DEP (pmap_setup, true),
                INIT_OP_DEP (printf_setup, true),
                INIT_OP_DEP (vm_map_bootstrap, true));

static int
vm_map_alloc_fault_pages (struct vm_map_entry *entry, struct vm_page **outp,
                          uint64_t offset, uintptr_t addr, uint64_t *startp)
{
  size_t adv = VM_MAP_ADVICE (entry->flags);
  assert (adv < ARRAY_SIZE (vm_map_page_targets));
  _Auto target = &vm_map_page_targets[adv];

  // Mind overflows when computing the offsets.
  uintptr_t start_off = MIN (addr - entry->start, target->front),
            last_off = MIN (entry->end - addr, target->back);
  uint32_t order = (uint32_t)(log2 ((last_off + start_off) >> PAGE_SHIFT));

  *startp = offset - start_off;
  *outp = vm_page_alloc (order, VM_PAGE_SEL_HIGHMEM,
                         VM_PAGE_OBJECT, VM_PAGE_SLEEP);
  return (*outp ? (int)order : -1);
}

static inline void
vm_map_cleanup_object (void *ptr)
{
  vm_object_unref (*(struct vm_object **)ptr);
}

static int
vm_map_fault_get_data (struct vm_object *obj, uint64_t off,
                       struct vm_page *pages, int prot, int nr_pages)
{
  int ret = -EINTR;

  if (!(obj->flags & VM_OBJECT_EXTERNAL))
    { // Simple callback-based object.
      uintptr_t va = vm_map_ipc_addr ();
      THREAD_PIN_GUARD ();
      _Auto pte = pmap_ipc_pte_get ();

      for (ret = 0; ret < nr_pages; ++ret, off += PAGE_SIZE)
        {
          pmap_ipc_pte_set (pte, va, vm_page_to_pa (pages + ret));
          int tmp = vm_object_pager_get (obj, off, PAGE_SIZE,
                                         prot, (void *)va);
          if (tmp < 0)
            {
              ret = tmp;
              break;
            }
        }

      pmap_ipc_pte_put (pte);
      return (ret);
    }

  // XXX: Implement for external pagers.
  return (ret);
}

static int
vm_map_fault_handle_cow (uintptr_t addr, struct vm_page **pgp,
                         struct vm_map *map, bool in_obj)
{
  thread_pin ();
  cpu_intr_enable ();

  _Auto p2 = vm_page_alloc (0, VM_PAGE_SEL_HIGHMEM,
                            VM_PAGE_OBJECT, VM_PAGE_SLEEP);
  if (! p2)
    {
      thread_unpin ();
      return (EINTR);
    }

  _Auto page = *pgp;
  uintptr_t va = vm_map_ipc_addr ();

  /*
   * We need both IPC PTEs to copy the page's contents because the virtual
   * address may not be mapped.
   */

  struct thread_pmap_data *ipc_dst = pmap_ipc_pte_get_idx (0),
                          *ipc_src = pmap_ipc_pte_get_idx (1);

  pmap_ipc_pte_set (ipc_dst, va, vm_page_to_pa (p2));
  pmap_ipc_pte_set (ipc_src, va + PAGE_SIZE, vm_page_to_pa (page));
  memcpy ((void *)va, (void *)(va + PAGE_SIZE), PAGE_SIZE);

  pmap_ipc_pte_put (ipc_dst);
  pmap_ipc_pte_put (ipc_src);
  cpu_intr_disable ();
  thread_unpin ();

  int ret = in_obj ? vm_object_swap (map->priv_cache, p2, page->offset, page) :
                     vm_object_insert (map->priv_cache, p2, page->offset);

  if (likely (ret == 0))
    {
      vm_page_ref (p2);
      *pgp = p2;
      // Removing the physical mapping will unreference the source page.
      pmap_remove (map->pmap, addr, 0);
    }
  else
    {
      cpu_intr_enable ();
      vm_page_unref (p2);
    }

  return (ret);
}

static bool
vm_map_fault_soft (struct vm_map *map, struct vm_object *obj, uint64_t off,
                   uintptr_t addr, int prot)
{
  bool in_obj = true;
  _Auto page = vm_object_lookup (obj, off);
  if (! page)
    {
      /*
       * The page wasn't found in the VM object. However, it's possible that
       * it's resident. This can happen with forked maps or COW pages.
       */

      if (obj != map->priv_cache)
        return (false);

      phys_addr_t tmp;
      if (pmap_extract (map->pmap, addr, &tmp) != 0)
        return (false);

      page = vm_page_lookup (tmp);
      if (!vm_page_is_cow (page))
        return (false);

      in_obj = false;
    }

  if ((prot & VM_PROT_WRITE) && vm_page_is_cow (page) &&
      vm_map_fault_handle_cow (addr, &page, map, in_obj) != 0)
    goto skip;
  else if (pmap_enter (map->pmap, addr, vm_page_to_pa (page),
                       prot, PMAP_IGNORE_ERRORS) == 0)
    pmap_update (map->pmap);

skip:
  vm_page_unref (page);
  atomic_add_rlx (&map->soft_faults, 1);
  return (true);
}

static void
vm_map_fault_free_pages (struct vm_page *frames, uint32_t n)
{
  cpu_intr_enable ();
  if (ISP2 (n))
    vm_page_free (frames, log2 (n), VM_PAGE_SLEEP);
  else
    for (uint32_t i = 0; i < n; ++i)
      vm_page_free (frames + i, 0, VM_PAGE_SLEEP);
  cpu_intr_disable ();
}

static int
vm_map_fault_impl (struct vm_map *map, uintptr_t addr, int prot)
{
  struct vm_map_entry *entry, tmp;
  struct vm_object *final_obj, *object;
  uint64_t final_off, offset;

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

    offset = entry->offset + addr - entry->start;
    if (entry->flags & VM_MAP_ANON)
      final_off = addr, final_obj = map->priv_cache;
    else
      final_off = offset, final_obj = object;

    if (vm_map_fault_soft (map, final_obj, final_off, addr, prot))
      return (0);

    // Prevent the VM object from going away as we drop the lock.
    vm_map_entry_copy (&tmp, entry);
    entry = &tmp;
  }

  cpu_intr_enable ();
  CLEANUP (vm_map_cleanup_object) __unused _Auto objg = object;
  struct vm_page *frames;
  uint64_t start_off;
  int n_pages = vm_map_alloc_fault_pages (entry, &frames, offset,
                                          addr, &start_off);

  if (n_pages < 0)
    // Allocation was interrupted. Let userspace handle things.
    return (0);

  n_pages = vm_map_fault_get_data (object, start_off, frames,
                                   prot, 1 << n_pages);
  if (n_pages < 0)
    return (-n_pages);
  else if (unlikely (start_off + n_pages * PAGE_SIZE < offset))
    /*
     * We didn't cover the faulting page. This is probably due to a truncated
     * object. Return an error that maps to SIGBUS.
     */
    return (EIO);

  cpu_intr_disable ();
  SXLOCK_SHGUARD (&map->lock);
  _Auto e2 = vm_map_lookup_nearest (map, addr);

  // Check that the entry is still valid and equal to the one we operated on.
  if (!(e2 && e2->object == entry->object &&
        addr >= e2->start &&
        (prot & VM_MAP_PROT (e2->flags)) == prot &&
        addr - (uintptr_t)(offset - start_off) +
          n_pages * PAGE_SIZE <= e2->end))
    {
      vm_map_fault_free_pages (frames, n_pages);
      goto retry;
    }

  prot = VM_MAP_PROT (e2->flags);
  addr -= offset - start_off;
  final_off -= offset - start_off;

  for (uint32_t i = 0; i < (uint32_t)n_pages;
      ++i, final_off += PAGE_SIZE, addr += PAGE_SIZE)
    {
      struct vm_page *page = frames + i;
      int error = vm_object_insert (final_obj, page, final_off);

      if (error != 0 ||
          pmap_enter (map->pmap, addr, vm_page_to_pa (page),
                      prot, PMAP_IGNORE_ERRORS) != 0)
        {
          i += error == 0;
          vm_map_fault_free_pages (frames + i, n_pages - i);
          break;
        }
    }

  pmap_update (map->pmap);
  atomic_add_rlx (&map->hard_faults, 1);
  return (0);
}

int
vm_map_fault (struct vm_map *map, uintptr_t addr, int prot)
{
  assert (map != vm_map_get_kernel_map ());
  assert (!cpu_intr_enabled ());
  int ret = vm_map_fault_impl (map, vm_page_trunc (addr), prot);
  cpu_intr_disable ();
  return (ret);
}

int
vm_map_create (struct vm_map **mapp)
{
  struct vm_map *map = kmem_cache_alloc (&vm_map_cache);
  if (! map)
    return (ENOMEM);

  struct pmap *pmap;
  int error = pmap_create (&pmap);
  if (error)
    goto error_pmap;

  struct vm_object *priv;
  error = vm_object_anon_create (&priv);
  if (error)
    goto error_priv;

  vm_map_init (map, pmap, PMAP_START_ADDRESS, PMAP_END_ADDRESS, priv);
  *mapp = map;
  return (0);

error_priv:
  pmap_destroy (pmap);
error_pmap:
  kmem_cache_free (&vm_map_cache, map);
  return (error);
}

int
vm_map_lookup (struct vm_map *map, uintptr_t addr,
               struct vm_map_entry *entry)
{
  SXLOCK_SHGUARD (&map->lock);
  _Auto ep = vm_map_lookup_nearest (map, addr);

  if (! ep)
    return (ESRCH);

  vm_map_entry_copy (entry, ep);
  return (0);
}

int
vm_map_anon_alloc (void **outp, struct vm_map *map, size_t size)
{
  if (!map->priv_cache)
    return (EINVAL);

  uintptr_t va = (map->end - map->start) >> 1;
  int flags = VM_MAP_FLAGS (VM_PROT_RDWR, VM_PROT_RDWR, VM_INHERIT_DEFAULT,
                            VM_ADV_DEFAULT, VM_MAP_ANON);
  int error = vm_map_enter (map, &va, vm_page_round (size), flags,
                            map->priv_cache, 0);
  if (! error)
    *outp = (void *)va;

  return (error);
}

static void
vm_map_destroy_impl (struct vm_map *map)
{
  rbtree_for_each_remove (&map->entry_tree, entry, tmp)
    vm_map_entry_destroy (rbtree_entry (entry, struct vm_map_entry,
                                        tree_node), true);
}

void
vm_map_destroy (struct vm_map *map)
{
  vm_map_destroy_impl (map);
  vm_object_unref (map->priv_cache);
  kmem_cache_free (&vm_map_cache, map);
}

#define VM_MAP_FORK_BUFSIZE   (16)

#if VM_MAP_FORK_BUFSIZE > PMAP_UPDATE_MAX_OPS
#  error "page buffer size too big"
#endif

static void
vm_map_fork_apply_prot (struct pmap *pmap, struct vm_map_fork_buf *buf, int n)
{
  for (int i = 0; i < n; ++i)
    {
      _Auto page = buf[i].page;
      int prot = buf[i].prot;
      uintptr_t va = vm_page_anon_va (page);

      if (prot & VM_PROT_WRITE)
        pmap_protect (pmap, va, prot & ~VM_PROT_WRITE, PMAP_PEF_GLOBAL);

      vm_page_set_cow (page);
    }

  pmap_update (pmap);
}

static int
vm_map_fork_apply_enter (struct pmap *pmap, struct vm_map_fork_buf *buf, int n)
{
  for (int i = 0; i < n; ++i)
    {
      _Auto page = buf[i].page;
      int prot = buf[i].prot;
      uintptr_t va = vm_page_anon_va (page);

      int error = pmap_enter (pmap, va, vm_page_to_pa (page),
                              prot & ~VM_PROT_WRITE,
                              PMAP_SET_COW | PMAP_PEF_GLOBAL);
      if (error)
        return (error);

      vm_page_ref (page);
    }

  return (pmap_update (pmap));
}

static int
vm_map_fork_flush (struct pmap *spmap, struct vm_map *dst,
                   struct vm_map_fork_buf *buf, int cnt)
{
  vm_map_fork_apply_prot (spmap, buf, cnt);
  int error = vm_map_fork_apply_enter (dst->pmap, buf, cnt);
  if (error)
    vm_map_destroy (dst);
  return (error);
}

int
vm_map_fork (struct vm_map **mapp, struct vm_map *src)
{
  int error = vm_map_create (mapp);
  if (error)
    return (error);

  struct vm_map *dst = *mapp;
  _Auto priv = src->priv_cache;
  _Auto pmap = src->pmap;

  SXLOCK_SHGUARD (&src->lock);
  MUTEX_GUARD (&priv->lock);   // Prevent modifications to private mappings.

  if (vm_map_entry_alloc (&dst->entry_list, src->nr_entries) != 0)
    {
      vm_map_destroy (dst);
      return (ENOMEM);
    }

  struct vm_map_entry *entry, *out;
  out = list_first_entry (&dst->entry_list, typeof (*out), list_node);

  list_for_each_entry (&src->entry_list, entry, list_node)
    {
      if (VM_MAP_INHERIT (entry->flags) == VM_INHERIT_NONE)
        continue;
      else if (entry->object != src->priv_cache ||
               VM_MAP_INHERIT (entry->flags) == VM_INHERIT_SHARE)
        vm_map_entry_copy (out, entry);
      else
        {
          vm_map_entry_copy_impl (out, entry);
          out->object = dst->priv_cache;
          vm_object_ref (out->object);
        }

      rbtree_insert (&dst->entry_tree, &out->tree_node,
                     vm_map_entry_cmp_insert);
      out = list_next_entry (out, list_node);
    }

  struct rdxtree_iter it;
  struct vm_page *page;
  struct vm_map_fork_buf buf[VM_MAP_FORK_BUFSIZE];
  int nr_buf = 0;

  rdxtree_for_each (&priv->pages, &it, page)
    {
      entry = vm_map_lookup_nearest (dst, vm_page_anon_va (page));
      if (!entry || VM_MAP_INHERIT (entry->flags) != VM_INHERIT_COPY)
        continue;

      buf[nr_buf] = (typeof (*buf)) { page, VM_MAP_PROT (entry->flags) };
      if (++nr_buf == (int)ARRAY_SIZE (buf))
        {
          error = vm_map_fork_flush (pmap, dst, buf, nr_buf);
          if (error)
            return (error);
        }
    }

  if (nr_buf)
    {
      error = vm_map_fork_flush (pmap, dst, buf, nr_buf);
      if (error)
        return (error);
    }

  dst->nr_entries = src->nr_entries;
  return (0);
}

static int
vm_map_iter_cleanup (struct vm_map *map, struct ipc_vme_iter *it,
                     uint32_t ix, int error)
{
  bool changed = false;
  for (; it->cur != ix; --it->cur)
    {
      _Auto page = it->begin + it->cur - 1;
      struct list entries;
      uintptr_t start = page->addr, end = start + page->size;

      list_init (&entries);
      vm_map_remove_impl (map, start, end, &entries, false);
      list_for_each_safe (&entries, ex, tmp)
        vm_map_entry_destroy (list_entry (ex, struct vm_map_entry,
                                          list_node), true);

      pmap_remove_range (map->pmap, start, end,
                         PMAP_PEF_GLOBAL | PMAP_IGNORE_ERRORS);
      changed = true;
    }

  if (changed)
    pmap_update (map->pmap);
  return (-error);
}

static void
vm_map_iter_fini (struct sxlock **lockp)
{
  if (*lockp)
    sxlock_unlock (*lockp);
}

int
vm_map_iter_copy (struct vm_map *r_map, struct ipc_vme_iter *r_it,
                  struct ipc_vme_iter *l_it, int direction)
{
  struct vm_map *in_map, *out_map;
  struct ipc_vme_iter *in_it, *out_it;

  if (direction == IPC_COPY_FROM)
    {
      in_map = r_map, out_map = vm_map_self ();
      in_it = r_it, out_it = l_it;
    }
  else
    {
      in_map = vm_map_self (), out_map = r_map;
      in_it = l_it, out_it = r_it;
    }

  uint32_t prev = out_it->cur;
  int i = 0, nmax = (int)MIN (ipc_vme_iter_size (in_it),
                              ipc_vme_iter_size (out_it));
  struct sxlock *lock CLEANUP (vm_map_iter_fini) = &in_map->lock;

  SXLOCK_EXGUARD (&out_map->lock);
  if (likely (in_map != out_map))
    sxlock_shlock (lock);
  else
    lock = NULL;

  for (; i < nmax; ++i, ++in_it->cur)
    {
      _Auto page = in_it->begin[in_it->cur];
      uintptr_t end = page.addr + vm_page_round (page.size);

      do
        {
          _Auto entry = vm_map_lookup_nearest (in_map, page.addr);
          _Auto outp = &out_it->begin[out_it->cur];

          if (! entry)
            return (vm_map_iter_cleanup (out_map, out_it, prev, ESRCH));
          else if ((VM_MAP_MAXPROT (entry->flags) & page.max_prot) !=
                   page.max_prot || (page.max_prot & page.prot) != page.prot)
            return (vm_map_iter_cleanup (out_map, out_it, prev, EACCES));

          size_t size = MIN (end - page.addr, page.size);
          if (! size)
            return (vm_map_iter_cleanup (out_map, out_it, prev, EINVAL));

          uint64_t offset = entry->offset + (page.addr - entry->start);
          int flags = VM_MAP_FLAGS (page.max_prot, page.prot,
                                    VM_MAP_INHERIT (entry->flags),
                                    VM_MAP_ADVICE (entry->flags), 0),
              error = vm_map_enter_locked (out_map, &outp->addr, size,
                                           flags, entry->object, offset);
          if (error)
            return (vm_map_iter_cleanup (out_map, out_it, prev, error));

          outp->prot = page.prot;
          outp->max_prot = page.max_prot;
          outp->size = size;
          page.addr += size;
          ++out_it->cur;
        }
      while (page.addr < end && ipc_vme_iter_size (out_it));
    }

  return (i);
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
