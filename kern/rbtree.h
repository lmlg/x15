/*
 * Copyright (c) 2010-2015 Richard Braun.
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
 *
 *
 * Red-black tree.
 */

#ifndef KERN_RBTREE_H
#define KERN_RBTREE_H

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include <kern/macros.h>

// Indexes of the left and right nodes in the children array of a node.
#define RBTREE_LEFT     0
#define RBTREE_RIGHT    1

// Insertion point identifier.
typedef uintptr_t rbtree_slot_t;

/*
 * Red-black node structure.
 *
 * To reduce the number of branches and the instruction cache footprint,
 * the left and right child pointers are stored in an array, and the symmetry
 * of most tree operations is exploited by using left/right variables when
 * referring to children.
 *
 * In addition, this implementation assumes that all nodes are 4-byte aligned,
 * so that the least significant bit of the parent member can be used to store
 * the color of the node. This is true for all modern 32 and 64 bits
 * architectures, as long as the nodes aren't embedded in structures with
 * special alignment constraints such as member packing.
 */
struct rbtree_node
{
  uintptr_t parent;
  struct rbtree_node *children[2];
};

// Red-black tree structure.
struct rbtree
{
  struct rbtree_node *root;
};

// Static tree initializer.
#define RBTREE_INITIALIZER   { NULL }

/*
 * Masks applied on the parent member of a node to obtain either the
 * color or the parent address.
 */
#define RBTREE_COLOR_MASK    ((uintptr_t)0x1)
#define RBTREE_PARENT_MASK   (~(uintptr_t)0x3)

// Node colors.
#define RBTREE_COLOR_RED     0
#define RBTREE_COLOR_BLACK   1

/*
 * Masks applied on slots to obtain either the child index or the parent
 * address.
 */
#define RBTREE_SLOT_INDEX_MASK    0x1UL
#define RBTREE_SLOT_PARENT_MASK   (~RBTREE_SLOT_INDEX_MASK)

// Return true if the given index is a valid child index.
static inline int
rbtree_check_index (int index)
{
  return (index == (index & 1));
}

/*
 * Convert the result of a comparison into an index in the children array
 * (0 or 1).
 *
 * This function is mostly used when looking up a node.
 */
static inline int
rbtree_d2i (int diff)
{
  return (diff > 0);
}

// Return true if the given pointer is suitably aligned.
static inline int
rbtree_node_check_alignment (const struct rbtree_node *node)
{
  return (((uintptr_t)node & ~RBTREE_PARENT_MASK) == 0);
}

// Return the parent of a node.
static inline struct rbtree_node*
rbtree_node_parent (const struct rbtree_node *node)
{
  return ((struct rbtree_node *)(node->parent & RBTREE_PARENT_MASK));
}

// Translate an insertion point into a slot.
static inline rbtree_slot_t
rbtree_slot (struct rbtree_node *parent, int index)
{
  assert (rbtree_node_check_alignment (parent));
  assert (rbtree_check_index (index));
  return ((rbtree_slot_t) parent | index);
}

// Extract the parent address from a slot.
static inline struct rbtree_node*
rbtree_slot_parent (rbtree_slot_t slot)
{
  return ((struct rbtree_node *)(slot & RBTREE_SLOT_PARENT_MASK));
}

// Extract the index from a slot.
static inline int
rbtree_slot_index (rbtree_slot_t slot)
{
  return (slot & RBTREE_SLOT_INDEX_MASK);
}

/*
 * Insert a node in a tree, rebalancing it if necessary.
 *
 * The index parameter is the index in the children array of the parent where
 * the new node is to be inserted. It is ignored if the parent is NULL.
 *
 * This function is intended to be used by the rbtree_insert() macro only.
 */
void rbtree_insert_rebalance (struct rbtree *tree, struct rbtree_node *parent,
                              int index, struct rbtree_node *node);

/*
 * Return the previous or next node relative to a location in a tree.
 *
 * The parent and index parameters define the location, which can be empty.
 * The direction parameter is either RBTREE_LEFT (to obtain the previous
 * node) or RBTREE_RIGHT (to obtain the next one).
 */
struct rbtree_node* rbtree_nearest (struct rbtree_node *parent, int index,
                                     int direction);

/*
 * Return the first or last node of a tree.
 *
 * The direction parameter is either RBTREE_LEFT (to obtain the first node)
 * or RBTREE_RIGHT (to obtain the last one).
 */
struct rbtree_node* rbtree_firstlast (const struct rbtree *tree, int direction);

/*
 * Return the node next to, or previous to the given node.
 *
 * The direction parameter is either RBTREE_LEFT (to obtain the previous node)
 * or RBTREE_RIGHT (to obtain the next one).
 */
struct rbtree_node* rbtree_walk (struct rbtree_node *node, int direction);

/*
 * Return the left-most deepest node of a tree, which is the starting point of
 * the postorder traversal performed by rbtree_for_each_remove().
 */
struct rbtree_node* rbtree_postwalk_deepest (const struct rbtree *tree);

// Unlink a node from its tree and return the next (right) node in postorder.
struct rbtree_node* rbtree_postwalk_unlink (struct rbtree_node *node);


// Initialize a tree.
static inline void
rbtree_init (struct rbtree *tree)
{
  tree->root = NULL;
}

/*
 * Initialize a node.
 *
 * A node is in no tree when its parent points to itself.
 */
static inline void
rbtree_node_init (struct rbtree_node *node)
{
  assert (rbtree_node_check_alignment (node));

  node->parent = (uintptr_t)node | RBTREE_COLOR_RED;
  node->children[RBTREE_LEFT] = NULL;
  node->children[RBTREE_RIGHT] = NULL;
}

// Return true if node is in no tree.
static inline int
rbtree_node_unlinked (const struct rbtree_node *node)
{
  return (rbtree_node_parent (node) == node);
}

/*
 * Macro that evaluates to the address of the structure containing the
 * given node based on the given type and member.
 */
#define rbtree_entry(node, type, member)   structof (node, type, member)

// Return true if tree is empty.
static inline int
rbtree_empty (const struct rbtree *tree)
{
  return (tree->root == NULL);
}

/*
 * Look up a node in a tree.
 *
 * Note that implementing the lookup algorithm as a macro gives two benefits:
 * First, it avoids the overhead of a callback function. Next, the type of the
 * cmp_fn parameter isn't rigid. The only guarantee offered by this
 * implementation is that the key parameter is the first parameter given to
 * cmp_fn. This way, users can pass only the value they need for comparison
 * instead of e.g. allocating a full structure on the stack.
 *
 * See rbtree_insert().
 */
#define rbtree_lookup(tree, key, cmp_fn)   \
MACRO_BEGIN   \
  \
  struct rbtree_node *cur_ = (tree)->root;   \
  \
  while (cur_ != NULL)   \
    {   \
      int diff_ = cmp_fn (key, cur_);   \
      if (! diff)   \
        break;   \
      \
      cur_ = cur_->children[rbtree_d2i (diff_)];   \
    }   \
  \
  cur_;   \
MACRO_END

/*
 * Look up a node or one of its nearest nodes in a tree.
 *
 * This macro essentially acts as rbtree_lookup() but if no entry matched
 * the key, an additional step is performed to obtain the next or previous
 * node, depending on the direction (left or right).
 *
 * The constraints that apply to the key parameter are the same as for
 * rbtree_lookup().
 */
#define rbtree_lookup_nearest(tree, key, cmp_fn, dir)   \
MACRO_BEGIN   \
  \
  struct rbtree_node *prev_ = NULL, *cur_ = (tree)->root;   \
  int index_ = -1;   \
  \
  while (cur_ != NULL)   \
    {   \
      int diff_ = cmp_fn (key, cur_);   \
      if (! diff_)   \
        break;   \
      \
      prev_ = cur_;   \
      index_ = rbtree_d2i (diff_);   \
      cur_ = cur_->children[index_];   \
    }   \
  \
  if (! cur_)   \
    cur_ = rbtree_nearest (prev_, index_, dir);   \
  \
  cur_;   \
MACRO_END

/*
 * Insert a node in a tree.
 *
 * This macro performs a standard lookup to obtain the insertion point of
 * the given node in the tree (it is assumed that the inserted node never
 * compares equal to any other entry in the tree) and links the node. It
 * then checks red-black rules violations, and rebalances the tree if
 * necessary.
 *
 * Unlike rbtree_lookup(), the cmp_fn parameter must compare two complete
 * entries, so it is suggested to use two different comparison inline
 * functions, such as myobj_cmp_lookup() and myobj_cmp_insert(). There is no
 * guarantee about the order of the nodes given to the comparison function.
 *
 * See rbtree_lookup().
 */
#define rbtree_insert(tree, node, cmp_fn)   \
MACRO_BEGIN   \
  \
  struct rbtree_node *prev_ = NULL, *cur_ = (tree)->root;   \
  int index_ = -1;   \
  cur_ = (tree)->root;                                    \
  \
  while (cur_ != NULL)   \
    {   \
      int diff_ = cmp_fn (node, cur_);   \
      assert (diff_);   \
      prev_ = cur_;   \
      index_ = rbtree_d2i (diff_);   \
      cur_ = cur_->children[index_];   \
    }   \
  \
  rbtree_insert_rebalance (tree, prev_, index_, node);   \
MACRO_END

/*
 * Look up a node/slot pair in a tree.
 *
 * This macro essentially acts as rbtree_lookup() but in addition to a node,
 * it also returns a slot, which identifies an insertion point in the tree.
 * If the returned node is NULL, the slot can be used by rbtree_insert_slot()
 * to insert without the overhead of an additional lookup.
 *
 * The constraints that apply to the key parameter are the same as for
 * rbtree_lookup().
 */
#define rbtree_lookup_slot(tree, key, cmp_fn, slot)   \
MACRO_BEGIN   \
  \
  struct rbtree_node *prev_ = NULL, *cur_ = (tree)->root;   \
  int index_ = 0;   \
  \
  while (cur_ != NULL)   \
    {   \
      int diff_ = cmp_fn (key, cur_);   \
      if (! diff_)   \
        break;   \
      \
      prev_ = cur_;   \
      index_ = rbtree_d2i (diff_);   \
      cur_ = cur_->children[index_];   \
    }   \
  \
  (slot) = rbtree_slot(prev_, index_);   \
  cur_;   \
MACRO_END

/*
 * Insert a node at an insertion point in a tree.
 *
 * This macro essentially acts as rbtree_insert() except that it doesn't
 * obtain the insertion point with a standard lookup. The insertion point
 * is obtained by calling rbtree_lookup_slot(). In addition, the new node
 * must not compare equal to an existing node in the tree (i.e. the slot
 * must denote a NULL node).
 */
static inline void
rbtree_insert_slot (struct rbtree *tree, rbtree_slot_t slot,
                    struct rbtree_node *node)
{
  struct rbtree_node *parent = rbtree_slot_parent (slot);
  int index = rbtree_slot_index (slot);
  rbtree_insert_rebalance (tree, parent, index, node);
}

/*
 * Replace a node at an insertion point in a tree.
 *
 * The given node must compare strictly equal to the previous node,
 * which is returned on completion.
 */
void* rbtree_replace_slot (struct rbtree *tree, rbtree_slot_t slot,
                           struct rbtree_node *node);

/*
 * Remove a node from a tree.
 *
 * After completion, the node is stale.
 */
void rbtree_remove (struct rbtree *tree, struct rbtree_node *node);

// Return the first node of a tree.
#define rbtree_first(tree)   rbtree_firstlast (tree, RBTREE_LEFT)

// Return the last node of a tree.
#define rbtree_last(tree)    rbtree_firstlast (tree, RBTREE_RIGHT)

// Return the node previous to the given node.
#define rbtree_prev(node)   rbtree_walk (node, RBTREE_LEFT)

// Return the node next to the given node.
#define rbtree_next(node)   rbtree_walk(node, RBTREE_RIGHT)

/*
 * Forge a loop to process all nodes of a tree, removing them when visited.
 *
 * This macro can only be used to destroy a tree, so that the resources used
 * by the entries can be released by the user. It basically removes all nodes
 * without doing any color checking.
 *
 * After completion, all nodes and the tree root member are stale.
 */
#define rbtree_for_each_remove(tree, node, tmp)   \
  for (struct rbtree_node *node = rbtree_postwalk_deepest (tree),   \
       *tmp = rbtree_postwalk_unlink (node);                \
       node != NULL;                                      \
       node = tmp, tmp = rbtree_postwalk_unlink (node))

#endif
