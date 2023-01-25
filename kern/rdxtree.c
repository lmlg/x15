/*
 * Copyright (c) 2011-2018 Richard Braun.
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
 * Upstream site with license notes :
 * http://git.sceen.net/rbraun/librbraun.git/
 */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <kern/init.h>
#include <kern/kmem.h>
#include <kern/macros.h>
#include <kern/rcu.h>
#include <kern/rdxtree.h>
#include <kern/work.h>

// Mask applied on an entry to obtain its address.
#define RDXTREE_ENTRY_ADDR_MASK   (~0x3UL)

// Global properties used to shape radix trees.
#define RDXTREE_RADIX        6
#define RDXTREE_RADIX_SIZE   (1UL << RDXTREE_RADIX)
#define RDXTREE_RADIX_MASK   (RDXTREE_RADIX_SIZE - 1)

#if RDXTREE_RADIX < 6
  typedef unsigned long rdxtree_bm_t;
  #define rdxtree_ffs(x) __builtin_ffsl(x)
#elif RDXTREE_RADIX == 6
  typedef unsigned long long rdxtree_bm_t;
  #define rdxtree_ffs(x) __builtin_ffsll(x)
#else
  #error "radix too high"
#endif

// Allocation bitmap size in bits.
#define RDXTREE_BM_SIZE   (sizeof (rdxtree_bm_t) * CHAR_BIT)

/*
 * Empty/full allocation bitmap words.
 */
#define RDXTREE_BM_EMPTY    ((rdxtree_bm_t)0)
#define RDXTREE_BM_FULL \
  ((~(rdxtree_bm_t)0) >> (RDXTREE_BM_SIZE - RDXTREE_RADIX_SIZE))

/*
 * Radix tree node.
 *
 * The height of a tree is the number of nodes to traverse until stored
 * pointers are reached. A height of 0 means the entries of a node (or the
 * tree root) directly point to stored pointers.
 *
 * The index is valid if and only if the parent isn't NULL.
 *
 * Concerning the allocation bitmap, a bit is set when the node it denotes,
 * or one of its children, can be used to allocate an entry. Conversely, a bit
 * is clear when the matching node and all of its children have no free entry.
 *
 * In order to support safe lockless lookups, in particular during a resize,
 * each node includes the height of its subtree, which is invariant during
 * the entire node lifetime. Since the tree height does vary, it can't be
 * used to determine whether the tree root is a node or a stored pointer.
 * This implementation assumes that all nodes and stored pointers are at least
 * 4-byte aligned, and uses the least significant bit of entries to indicate
 * the pointer type. This bit is set for internal nodes, and clear for stored
 * pointers so that they can be accessed from slots without conversion.
 */
struct rdxtree_node
{
  union
    {
      struct
        {
          struct rdxtree_node *parent;
          uint16_t index;
        };

      // Deferred destruction when unlinked.
      struct work work;
    };

  uint16_t height;
  uint16_t nr_entries;
  rdxtree_bm_t alloc_bm;
  void *entries[RDXTREE_RADIX_SIZE];
};

static struct kmem_cache rdxtree_node_cache;

static bool
rdxtree_alignment_valid (const void *ptr)
{
  return (((uintptr_t) ptr & ~RDXTREE_ENTRY_ADDR_MASK) == 0);
}

static inline void*
rdxtree_entry_addr (void *entry)
{
  return ((void *)((uintptr_t) entry & RDXTREE_ENTRY_ADDR_MASK));
}

static inline bool
rdxtree_entry_is_node (const void *entry)
{
  return (((uintptr_t) entry & 1) != 0);
}

static inline void*
rdxtree_node_to_entry (struct rdxtree_node *node)
{
  return ((void *)((uintptr_t) node | 1));
}

static void
rdxtree_node_ctor (void *buf)
{
  struct rdxtree_node *node = buf;
  node->nr_entries = 0;
  node->alloc_bm = RDXTREE_BM_FULL;
  memset (node->entries, 0, sizeof (node->entries));
}

static int
rdxtree_node_create (struct rdxtree_node **nodep, uint16_t height)
{
  struct rdxtree_node *node = kmem_cache_salloc (&rdxtree_node_cache);
  if (! node)
    return (ENOMEM);

  assert (rdxtree_alignment_valid (node));
  node->parent = NULL;
  node->height = height;
  *nodep = node;
  return (0);
}

static void
rdxtree_node_destroy (struct rdxtree_node *node)
{
  // See rdxtree_shrink().
  if (node->nr_entries)
    {
      assert (node->entries[0]);
      for (uint32_t i = 0; i < node->nr_entries; ++i)
        node->entries[i] = NULL;

      node->nr_entries = 0;
      node->alloc_bm = RDXTREE_BM_FULL;
    }

  kmem_cache_free (&rdxtree_node_cache, node);
}

static void
rdxtree_node_destroy_deferred (struct work *work)
{
  rdxtree_node_destroy (structof (work, struct rdxtree_node, work));
}

static void
rdxtree_node_schedule_destruction (struct rdxtree_node *node)
{
  assert (!node->parent);

  work_init (&node->work, rdxtree_node_destroy_deferred);
  rcu_defer (&node->work);
}

static inline void
rdxtree_node_link (struct rdxtree_node *node, struct rdxtree_node *parent,
                   uint16_t index)
{
  node->parent = parent;
  node->index = index;
}

static inline void
rdxtree_node_unlink (struct rdxtree_node *node)
{
  assert (node->parent);
  node->parent = NULL;
}

static inline bool
rdxtree_node_full (struct rdxtree_node *node)
{
  return (node->nr_entries == ARRAY_SIZE (node->entries));
}

static inline bool
rdxtree_node_empty (struct rdxtree_node *node)
{
  return (!node->nr_entries);
}

static inline void
rdxtree_node_insert (struct rdxtree_node *node, uint16_t index, void *entry)
{
  assert (index < ARRAY_SIZE (node->entries));
  assert (!node->entries[index]);

  ++node->nr_entries;
  rcu_store (&node->entries[index], entry);
}

static inline void
rdxtree_node_insert_node (struct rdxtree_node *node, uint16_t index,
                          struct rdxtree_node *child)
{
  rdxtree_node_insert (node, index, rdxtree_node_to_entry (child));
}

static inline void
rdxtree_node_remove (struct rdxtree_node *node, uint16_t index)
{
  assert (index < ARRAY_SIZE (node->entries));
  assert (node->entries[index]);

  --node->nr_entries;
  rcu_store (&node->entries[index], NULL);
}

static inline void*
rdxtree_node_find (struct rdxtree_node *node, uint16_t *indexp)
{
  for (uint16_t index = *indexp; index < ARRAY_SIZE (node->entries); ++index)
    {
      void *ptr = rdxtree_entry_addr (rcu_load (&node->entries[index]));

      if (ptr)
        {
          *indexp = index;
          return (ptr);
        }
    }

  return (NULL);
}

static inline void
rdxtree_node_bm_set (struct rdxtree_node *node, uint16_t index)
{
  node->alloc_bm |= (rdxtree_bm_t) 1 << index;
}

static inline void
rdxtree_node_bm_clear (struct rdxtree_node *node, uint16_t index)
{
  node->alloc_bm &= ~ ((rdxtree_bm_t) 1 << index);
}

static inline bool
rdxtree_node_bm_is_set (struct rdxtree_node *node, uint16_t index)
{
  return (node->alloc_bm & ((rdxtree_bm_t) 1 << index));
}

static inline bool
rdxtree_node_bm_empty (struct rdxtree_node *node)
{
  return (node->alloc_bm == RDXTREE_BM_EMPTY);
}

static inline uint16_t
rdxtree_node_bm_first (struct rdxtree_node *node)
{
  return (rdxtree_ffs (node->alloc_bm) - 1);
}

static inline rdxtree_key_t
rdxtree_max_key (uint16_t height)
{
  size_t shift = RDXTREE_RADIX * height;

  if (likely (shift < sizeof (rdxtree_key_t) * CHAR_BIT))
    return (((rdxtree_key_t) 1 << shift) - 1);
  else
    return (~((rdxtree_key_t) 0));
}

static inline bool
rdxtree_key_alloc_enabled (const struct rdxtree *tree)
{
  return (tree->flags & RDXTREE_KEY_ALLOC);
}

static void
rdxtree_shrink (struct rdxtree *tree)
{
  while (tree->height > 0)
    {
      struct rdxtree_node *node = rdxtree_entry_addr (tree->root);
      if (node->nr_entries != 1)
        break;

      void *entry = node->entries[0];

      if (! entry)
        break;
      else if (--tree->height > 0)
        rdxtree_node_unlink (rdxtree_entry_addr (entry));

      rcu_store (&tree->root, entry);

      /*
       * There is still one valid entry (the first one) in this node. It
       * must remain valid as long as read-side references can exist so
       * that concurrent lookups can find the rest of the tree. Therefore,
       * this entry isn't reset before node destruction.
       */
      rdxtree_node_schedule_destruction (node);
    }
}

static int
rdxtree_grow (struct rdxtree *tree, rdxtree_key_t key)
{
  uint16_t new_height = tree->height + 1;
  while (key > rdxtree_max_key (new_height))
    new_height++;

  if (!tree->root)
    {
      tree->height = new_height;
      return (0);
    }

  struct rdxtree_node *root = rdxtree_entry_addr (tree->root);

  do
    {
      struct rdxtree_node *node;
      int error = rdxtree_node_create (&node, tree->height);

      if (error)
        {
          rdxtree_shrink (tree);
          return (error);
        }
      else if (tree->height)
        {
          rdxtree_node_link (root, node, 0);

          if (rdxtree_key_alloc_enabled (tree) &&
              rdxtree_node_bm_empty (root))
            rdxtree_node_bm_clear (node, 0);
        }
      else if (rdxtree_key_alloc_enabled (tree))
        rdxtree_node_bm_clear (node, 0);
        

      rdxtree_node_insert (node, 0, tree->root);
      ++tree->height;
      rcu_store (&tree->root, rdxtree_node_to_entry (node));
      root = node;
    }
  while (new_height > tree->height);

  return (0);
}

static void
rdxtree_cleanup (struct rdxtree *tree, struct rdxtree_node *node)
{
  while (1)
    {
      if (likely (!rdxtree_node_empty (node)))
        {
          if (unlikely (!node->parent))
            rdxtree_shrink (tree);

          break;
        }

      if (node->parent == NULL)
        {
          tree->height = 0;
          rcu_store (&tree->root, NULL);
          rdxtree_node_schedule_destruction (node);
          break;
        }

      struct rdxtree_node *prev = node;
      node = node->parent;
      rdxtree_node_unlink (prev);
      rdxtree_node_remove (node, prev->index);
      rdxtree_node_schedule_destruction (prev);
    }
}

static void
rdxtree_insert_bm_clear (struct rdxtree_node *node, uint16_t index)
{
  while (1)
    {
      rdxtree_node_bm_clear (node, index);

      if (!rdxtree_node_full (node) || !node->parent)
        break;

      index = node->index;
      node = node->parent;
    }
}

int
rdxtree_insert_common (struct rdxtree *tree, rdxtree_key_t key,
                       void *ptr, void ***slotp)
{
  assert (ptr);
  assert (rdxtree_alignment_valid (ptr));

  if (unlikely (key > rdxtree_max_key (tree->height)))
    {
      int error = rdxtree_grow (tree, key);
      if (error)
        return (error);
    }

  uint16_t height = tree->height;

  if (unlikely (! height))
    {
      if (slotp)
        *slotp = &tree->root;
      if (tree->root)
        return (EBUSY);

      rcu_store (&tree->root, ptr);

      return (0);
    }

  struct rdxtree_node *node = rdxtree_entry_addr (tree->root),
                      *prev = NULL;
  uint16_t index = 0, shift = (height - 1) * RDXTREE_RADIX;

  do
    {
      if (! node)
        {
          int error = rdxtree_node_create (&node, height - 1);

          if (error)
            {
              if (! prev)
                tree->height = 0;
              else
                rdxtree_cleanup (tree, prev);

              return (error);
            }

          if (! prev)
            rcu_store (&tree->root, rdxtree_node_to_entry (node));
          else
            {
              rdxtree_node_link (node, prev, index);
              rdxtree_node_insert_node (prev, index, node);
            }
        }

      prev = node;
      index = (uint16_t) (key >> shift) & RDXTREE_RADIX_MASK;
      node = rdxtree_entry_addr (prev->entries[index]);
      shift -= RDXTREE_RADIX;
      --height;
    }
  while (height > 0);

  if (slotp)
    *slotp = &prev->entries[index];

  if (unlikely (node))
    return (EBUSY);

  rdxtree_node_insert (prev, index, ptr);

  if (rdxtree_key_alloc_enabled (tree))
    rdxtree_insert_bm_clear (prev, index);

  return (0);
}

int
rdxtree_insert_alloc_common (struct rdxtree *tree, void *ptr,
                             rdxtree_key_t *keyp, void ***slotp)
{
  rdxtree_key_t key;
  int error;

  assert (rdxtree_key_alloc_enabled (tree));
  assert (ptr);
  assert (rdxtree_alignment_valid (ptr));

  uint16_t height = tree->height;

  if (unlikely (! height))
    {
      if (!tree->root)
        {
          rcu_store (&tree->root, ptr);
          *keyp = 0;

          if (slotp != NULL)
            *slotp = &tree->root;

          return (0);
        }

      goto grow;
    }

  struct rdxtree_node *node = rdxtree_entry_addr (tree->root),
                      *prev = NULL;
  uint16_t index = 0, shift = (height - 1) * RDXTREE_RADIX;
  key = 0;

  do
    {
      if (! node)
        {
          error = rdxtree_node_create (&node, height - 1);

          if (error)
            {
              rdxtree_cleanup (tree, prev);
              return (error);
            }

          rdxtree_node_link (node, prev, index);
          rdxtree_node_insert_node (prev, index, node);
        }

      prev = node;
      index = rdxtree_node_bm_first (node);

      if (index == UINT16_MAX)
        goto grow;

      key |= (rdxtree_key_t)index << shift;
      node = rdxtree_entry_addr (node->entries[index]);
      shift -= RDXTREE_RADIX;
      --height;
    }
  while (height > 0);

  rdxtree_node_insert (prev, index, ptr);
  rdxtree_insert_bm_clear (prev, index);

  if (slotp)
    *slotp = &prev->entries[index];

  goto out;

grow:
  key = rdxtree_max_key (height) + 1;
  error = rdxtree_insert_common (tree, key, ptr, slotp);

  if (error)
    return (error);

out:
  *keyp = key;
  return (0);
}

static void
rdxtree_remove_bm_set (struct rdxtree_node *node, uint16_t index)
{
  do
    {
      rdxtree_node_bm_set (node, index);

      if (!node->parent)
        break;

      index = node->index;
      node = node->parent;
    }
  while (!rdxtree_node_bm_is_set (node, index));
}

void*
rdxtree_remove (struct rdxtree *tree, rdxtree_key_t key)
{
  uint16_t height = tree->height;

  if (unlikely (key > rdxtree_max_key (height)))
    return (NULL);

  struct rdxtree_node *prev, *node = rdxtree_entry_addr (tree->root);

  if (unlikely (! height))
    {
      rcu_store (&tree->root, NULL);
      return (node);
    }

  uint16_t index, shift = (height - 1) * RDXTREE_RADIX;

  do
    {
      if (! node)
        return (NULL);

      prev = node;
      index = (uint16_t) (key >> shift) & RDXTREE_RADIX_MASK;
      node = rdxtree_entry_addr (node->entries[index]);
      shift -= RDXTREE_RADIX;
      --height;
    }
  while (height > 0);

  if (! node)
    return (NULL);

  if (rdxtree_key_alloc_enabled (tree))
    rdxtree_remove_bm_set (prev, index);

  rdxtree_node_remove (prev, index);
  rdxtree_cleanup (tree, prev);
  return (node);
}

void*
rdxtree_lookup_common (const struct rdxtree *tree, rdxtree_key_t key,
                       bool get_slot)
{
  struct rdxtree_node *node;
  uint16_t height;
  void *entry = rcu_load (&tree->root);

  if (! entry)
    {
      node = NULL;
      height = 0;
    }
  else
    {
      node = rdxtree_entry_addr (entry);
      height = rdxtree_entry_is_node (entry) ? node->height + 1 : 0;
    }

  if (key > rdxtree_max_key (height))
    return (NULL);
  else if (! height)
    return (node && get_slot ? (void *)&tree->root : node);

  uint16_t index, shift = (height - 1) * RDXTREE_RADIX;
  struct rdxtree_node *prev;

  do
    {
      if (! node)
        return (NULL);

      prev = node;
      index = (uint16_t) (key >> shift) & RDXTREE_RADIX_MASK;
      entry = rcu_load (&node->entries[index]);
      node = rdxtree_entry_addr (entry);
      shift -= RDXTREE_RADIX;
      --height;
    }
  while (height > 0);

  return (node && get_slot ? (void *)&prev->entries[index] : node);
}

void*
rdxtree_replace_slot (void **slot, void *ptr)
{
  assert (ptr);
  assert (rdxtree_alignment_valid (ptr));

  void *old = *slot;
  assert (old);
  assert (rdxtree_alignment_valid (old));
  rcu_store (slot, ptr);
  return (old);
}

static void*
rdxtree_walk_next (struct rdxtree *tree, struct rdxtree_iter *iter)
{
  void *entry = rcu_load (&tree->root);
  if (! entry)
    return (NULL);
  else if (!rdxtree_entry_is_node (entry))
    {
      if (iter->key != (rdxtree_key_t)-1)
        return (NULL);
      else
        {
          iter->key = 0;
          return (rdxtree_entry_addr (entry));
        }
    }

  rdxtree_key_t key = iter->key + 1;
  if (!key && iter->node)
    return (NULL);

  struct rdxtree_node *root, *node, *prev;
  uint16_t height, shift, index, orig_index;

  root = rdxtree_entry_addr (entry);
restart:
  node = root;
  height = root->height + 1;

  if (key > rdxtree_max_key (height))
    return (NULL);

  shift = (height - 1) * RDXTREE_RADIX;

  do
    {
      prev = node;
      index = (key >> shift) & RDXTREE_RADIX_MASK;
      orig_index = index;
      node = rdxtree_node_find (node, &index);

      if (! node)
        {
          shift += RDXTREE_RADIX;
          key = ((key >> shift) + 1) << shift;

          if (! key)
            return (NULL);

          goto restart;
        }

      if (orig_index != index)
        key = ((key >> shift) + (index - orig_index)) << shift;

      shift -= RDXTREE_RADIX;
      --height;
    }
  while (height > 0);

  iter->node = prev;
  iter->key = key;
  return (node);
}

void*
rdxtree_walk (struct rdxtree *tree, struct rdxtree_iter *iter)
{
  if (!iter->node)
    return (rdxtree_walk_next (tree, iter));

  uint16_t index = (iter->key + 1) & RDXTREE_RADIX_MASK;
  if (index)
    {
      uint16_t orig_index = index;
      void *ptr = rdxtree_node_find (iter->node, &index);

      if (ptr)
        {
          iter->key += (index - orig_index) + 1;
          return (ptr);
        }
    }

  return (rdxtree_walk_next (tree, iter));
}

void
rdxtree_remove_all (struct rdxtree *tree)
{
  if (!tree->height)
    {
      if (tree->root)
        rcu_store (&tree->root, NULL);

      return;
    }

  while (1)
    {
      struct rdxtree_iter iter;
      rdxtree_iter_init (&iter);
      rdxtree_walk_next (tree, &iter);

      if (!iter.node)
        break;

      struct rdxtree_node *node = iter.node,
                          *parent = node->parent;

      if (! parent)
        rdxtree_init (tree, tree->flags);
      else
        {
          if (rdxtree_key_alloc_enabled (tree))
            rdxtree_remove_bm_set (parent, node->index);

          rdxtree_node_remove (parent, node->index);
          rdxtree_cleanup (tree, parent);
          node->parent = NULL;
        }

      rdxtree_node_schedule_destruction (node);
    }
}

static int __init
rdxtree_setup (void)
{
  kmem_cache_init (&rdxtree_node_cache, "rdxtree_node",
                   sizeof (struct rdxtree_node), 0,
                   rdxtree_node_ctor, KMEM_CACHE_PAGE_ONLY);
  return (0);
}

INIT_OP_DEFINE (rdxtree_setup,
                INIT_OP_DEP (kmem_bootstrap, true),
                INIT_OP_DEP (rcu_bootstrap, true));
