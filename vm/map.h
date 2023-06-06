/*
 * Copyright (c) 2011-2019 Richard Braun.
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
 * Virtual memory map management.
 */

#ifndef VM_VM_MAP_H
#define VM_VM_MAP_H

#include <stdint.h>

#include <kern/init.h>
#include <kern/list.h>
#include <kern/rbtree.h>
#include <kern/stream.h>
#include <kern/sxlock.h>

#include <machine/pmap.h>

#include <vm/defs.h>
#include <vm/object.h>

/*
 * Mapping flags.
 *
 * Unless otherwise mentioned, these can also be used as map entry flags.
 */
#define VM_MAP_NOMERGE   0x10000
#define VM_MAP_FIXED     0x20000   // Not an entry flag.
#define VM_MAP_ANON      0x40000

// Macro used to forge "packed" flags.
#define VM_MAP_FLAGS(prot, maxprot, inherit, advice, mapflags)   \
  ((prot) | ((maxprot) << 4) | ((inherit) << 8) |   \
   ((advice) << 12) | (mapflags))

/*
 * Flags usable as map entry flags.
 *
 * Map entry flags also use the packed format.
 */
#define VM_MAP_ENTRY_MASK   (VM_MAP_NOMERGE | VM_MAP_ANON | 0xffff)

// Macros used to extract specific properties out of packed flags.
#define VM_MAP_PROT(flags)      ((flags) & 0xf)
#define VM_MAP_MAXPROT(flags)   (((flags) & 0xf0) >> 4)
#define VM_MAP_INHERIT(flags)   (((flags) & 0xf00) >> 8)
#define VM_MAP_ADVICE(flags)    (((flags) & 0xf000) >> 12)

// Macros used to set specific properties in packed flags.
#define VM_MAP_SET_PROP(flagp, val, mask, shift)   \
  do   \
    {   \
      _Auto flagp_ = (flagp);   \
      *flagp_ = (*flagp_ & ~(mask)) | ((val) << (shift));   \
    }   \
  while (0)

#define VM_MAP_SET_PROT(flagp, prot)   VM_MAP_SET_PROP (flagp, prot, 0xf, 0)

#define VM_MAP_SET_MAXPROT(flagp, prot)   \
  VM_MAP_SET_PROP (flagp, prot, 0xf0, 4)

#define VM_MAP_SET_INHERIT(flagp, x)   VM_MAP_SET_PROP (flagp, x, 0xf00, 8)
#define VM_MAP_SET_ADVICE(flagp, x)    VM_MAP_SET_PROP (flagp, x, 0xf000, 12)

// Flags for vm_map_fault.
#define VM_MAP_FAULT_INTR   0x01   // Enable interrupts.

// Memory range descriptor.
struct vm_map_entry
{
  struct list list_node;
  struct rbtree_node tree_node;
  uintptr_t start;
  uintptr_t end;
  struct vm_object *object;
  uint64_t offset;
  int flags;
};

// Memory map.
struct vm_map
{
  struct sxlock lock;
  struct list entry_list;
  struct rbtree entry_tree;
  uint32_t nr_entries;
  uintptr_t start;
  uintptr_t end;
  size_t size;
  struct vm_map_entry *lookup_cache;
  struct vm_object *priv_cache;
  struct pmap *pmap;
  uint32_t soft_faults;
  uint32_t hard_faults;
};

struct ipc_page_iter;

static inline struct vm_map*
vm_map_get_kernel_map (void)
{
  extern struct vm_map vm_map_kernel_map;
  return (&vm_map_kernel_map);
}

// Get the kernel virtual address used in IPC routines.
uintptr_t vm_map_ipc_addr (void);

// Get the current task's VM map.
#define vm_map_self()   ((struct vm_map *)thread_self()->task->map)

// Create a virtual mapping.
int vm_map_enter (struct vm_map *map, uintptr_t *startp,
                  size_t size, size_t align, int flags,
                  struct vm_object *object, uint64_t offset);

// Remove mappings from start to end.
int vm_map_remove (struct vm_map *map, uintptr_t start, uintptr_t end);

// Create a VM map.
int vm_map_create (struct vm_map **mapp);

// Create a fork of a VM map.
int vm_map_fork (struct vm_map **mapp, struct vm_map *src);

/*
 * Lookup an entry in a VM map.
 *
 * Note that the returned entry may not contain the address, and instead
 * compare strictly less than it. The VM object of the entry is referenced
 * prior to returning to guarantee its existence, so normally 'vm_map_entry_put'
 * must be called on the entry. */
int vm_map_lookup (struct vm_map *map, uintptr_t addr,
                   struct vm_map_entry *entry);

// Put back a previously returned entry.
static inline void
vm_map_entry_put (struct vm_map_entry *entry)
{
  struct vm_object *obj = entry->object;
  if (obj)
    vm_object_unref (obj);
}

// Handle a page fault. Interrupts must be disabled when calling this function.
int vm_map_fault (struct vm_map *map, uintptr_t addr, int prot);

// Destroy a VM map.
void vm_map_destroy (struct vm_map *map);

// Safely copy bytes to and from arbitrary buffers.
int vm_copy (void *dst, const void *src, size_t size);

// Allocate anonymous memory in a VM map.
int vm_map_anon_alloc (void **outp, struct vm_map *map, size_t size);

// Transfer pages between a remote and the local VM map.
int vm_map_iter_copy (struct vm_map *r_map, struct ipc_page_iter *r_it,
                      struct ipc_page_iter *l_it, int direction);

// Display information about a memory map.
void vm_map_info (struct vm_map *map, struct stream *stream);

/*
 * This init operation provides :
 *  - kernel mapping operations
 */
INIT_OP_DECLARE (vm_map_bootstrap);

/*
 * This init operation provides :
 *  - VM map creation
 *  - module fully initialized
 */
INIT_OP_DECLARE (vm_map_setup);

#endif
