/*
 * Copyright (c) 2009-2017 Richard Braun.
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
 * Doubly-linked list.
 */

#ifndef KERN_LIST_H
#define KERN_LIST_H

#include <stdbool.h>
#include <stddef.h>

#include <kern/list_types.h>
#include <kern/macros.h>
#include <kern/rcu.h>

/*
 * Structure used as both head and node.
 *
 * This implementation relies on using the same type for both heads and nodes.
 *
 * It is recommended to encode the use of struct list variables in their names,
 * e.g. struct list free_list or struct list free_objects is a good hint for a
 * list of free objects. A declaration like struct list free_node clearly
 * indicates it is used as part of a node in the free list.
 */
struct list;

// Static list initializer.
#define LIST_INITIALIZER(list)   { &(list), &(list) }

// Initialize a list.
static inline void
list_init (struct list *list)
{
  list->prev = list;
  list->next = list;
}

/*
 * Initialize a list node.
 *
 * A node is in no list when its node members point to NULL.
 */
static inline void
list_node_init (struct list *node)
{
  node->prev = NULL;
  node->next = NULL;
}

// Return true if node is in no list.
static inline bool
list_node_unlinked (const struct list *node)
{
  return (!node->prev);
}

// Return the first node of a list.
static inline struct list*
list_first (const struct list *list)
{
  return (list->next);
}

// Return the last node of a list.
static inline struct list*
list_last (const struct list *list)
{
  return (list->prev);
}

// Return the node next to the given node.
static inline struct list*
list_next (const struct list *node)
{
  return (node->next);
}

// Return the node previous to the given node.
static inline struct list*
list_prev (const struct list *node)
{
  return (node->prev);
}

// Return true if node is invalid and denotes one of the ends of the list.
static inline bool
list_end (const struct list *list, const struct list *node)
{
  return (list == node);
}

// Return true if list is empty.
static inline bool
list_empty (const struct list *list)
{
  return (list == list->next);
}

// Return true if list contains exactly one node.
static inline bool
list_singular (const struct list *list)
{
  return (!list_empty (list) && list->next == list->prev);
}

/*
 * Split list2 by moving its nodes up to, but not including, the given
 * node into list1, which can be in a stale state.
 *
 * If list2 is empty, or node is list2 or list2->next, list1 is merely
 * initialized.
 */
static inline void
list_split (struct list *list1, struct list *list2, struct list *node)
{
  if (list_empty (list2) || list2->next == node || list_end (list2, node))
    {
      list_init (list1);
      return;
    }

  list1->next = list2->next;
  list1->next->prev = list1;

  list1->prev = node->prev;
  node->prev->next = list1;

  list2->next = node;
  node->prev = list2;
}

/*
 * Append the nodes of list2 at the end of list1.
 *
 * After completion, list2 is stale.
 */
static inline void
list_concat (struct list *list1, const struct list *list2)
{
  if (list_empty (list2))
    return;

  struct list *last1 = list1->prev,
              *first2 = list2->next,
              *last2 = list2->prev;

  last1->next = first2;
  first2->prev = last1;

  last2->next = list1;
  list1->prev = last2;
}

/*
 * Set the new head of a list.
 *
 * This function is an optimized version of :
 * list_init(&new_list);
 * list_concat(&new_list, &old_list);
 *
 * After completion, old_head is stale.
 */
static inline void
list_set_head (struct list *new_head, const struct list *old_head)
{
  if (list_empty (old_head))
    {
      list_init (new_head);
      return;
    }

  *new_head = *old_head;
  new_head->next->prev = new_head;
  new_head->prev->next = new_head;
}

/*
 * Add a node between two nodes.
 *
 * This function is private.
 */
static inline void
list_add (struct list *prev, struct list *next, struct list *node)
{
  next->prev = node;
  node->next = next;

  prev->next = node;
  node->prev = prev;
}

// Insert a node at the head of a list.
static inline void
list_insert_head (struct list *list, struct list *node)
{
  list_add (list, list->next, node);
}

// Insert a node at the tail of a list.
static inline void
list_insert_tail (struct list *list, struct list *node)
{
  list_add (list->prev, list, node);
}

// Insert a node before another node.
static inline void
list_insert_before (struct list *node, struct list *next)
{
  list_add (next->prev, next, node);
}

// Insert a node after another node.
static inline void
list_insert_after (struct list *node, struct list *prev)
{
  list_add (prev, prev->next, node);
}

/*
 * Remove a node from a list.
 *
 * After completion, the node is stale.
 */
static inline void
list_remove (struct list *node)
{
  node->prev->next = node->next;
  node->next->prev = node->prev;
}

/*
 * Macro that evaluates to the address of the structure containing the
 * given node based on the given type and member.
 */
#define list_entry(node, type, member)   structof (node, type, member)

// Get the first entry of a list.
#define list_first_entry(list, type, member)   \
  list_entry (list_first (list), type, member)

// Get the last entry of a list.
#define list_last_entry(list, type, member) \
  list_entry (list_last (list), type, member)

// Get the entry next to the given entry.
#define list_next_entry(entry, member)   \
  list_entry (list_next (&(entry)->member), typeof (*(entry)), member)

// Get the entry previous to the given entry.
#define list_prev_entry(entry, member)   \
  list_entry (list_prev (&(entry)->member), typeof (*(entry)), member)

/*
 * Forge a loop to process all nodes of a list.
 *
 * The node must not be altered during the loop.
 */
#define list_for_each(lst, node)   \
  for (struct list *node = list_first (lst);   \
       !list_end (lst, node);   \
       node = list_next (node))

// Forge a loop to process all nodes of a list.
#define list_for_each_safe(lst, node, tmp)   \
  for (struct list *node = list_first (lst), *tmp = list_next (node);   \
       !list_end (lst, node);   \
       node = tmp, tmp = list_next (node))

// Version of list_for_each() that processes nodes backward.
#define list_for_each_reverse(list, node)   \
  for (node = list_last (list);   \
       !list_end (list, node);   \
       node = list_prev (node))

// Version of list_for_each_safe() that processes nodes backward.
#define list_for_each_reverse_safe(lst, node, tmp)   \
  for (struct list *node = list_last (lst), tmp = list_prev (node);   \
       !list_end (lst, node);   \
       node = tmp, tmp = list_prev (node))

/*
 * Forge a loop to process all entries of a list.
 *
 * The entry node must not be altered during the loop.
 */
#define list_for_each_entry(list, entry, member)   \
  for (entry = list_first_entry (list, typeof (*entry), member);   \
       !list_end (list, &entry->member);   \
       entry = list_next_entry (entry, member))

// Forge a loop to process all entries of a list.
#define list_for_each_entry_safe(list, entry, tmp, member)   \
  for (entry = list_first_entry (list, typeof (*entry), member),   \
       tmp = list_next_entry (entry, member);   \
       !list_end (list, &entry->member);   \
       entry = tmp, tmp = list_next_entry (entry, member))

// Version of list_for_each_entry() that processes entries backward.
#define list_for_each_entry_reverse(list, entry, member)   \
  for (entry = list_last_entry (list, typeof (*entry), member);   \
       !list_end (list, &entry->member);   \
       entry = list_prev_entry (entry, member))

// Version of list_for_each_entry_safe() that processes entries backward.
#define list_for_each_entry_reverse_safe(list, entry, tmp, member)   \
  for (entry = list_last_entry (list, typeof(*entry), member),   \
       tmp = list_prev_entry (entry, member);   \
       !list_end (list, &entry->member);   \
       entry = tmp, tmp = list_prev_entry (entry, member))

// Pop an element from a list.
#define list_pop(lst, type, member)   \
  ({   \
     _Auto tmp_ = list_first_entry (lst, type, member);   \
     list_remove (&tmp_->member);   \
     tmp_;   \
   })

/*
 * Lockless variants
 *
 * This is a subset of the main interface that only supports forward traversal.
 * In addition, list_end() is also allowed in read-side critical sections.
 */

// Return the first node of a list.
static inline struct list*
list_rcu_first (const struct list *list)
{
  return (rcu_load (&list->next));
}

// Return the node next to the given node.
static inline struct list*
list_rcu_next (const struct list *node)
{
  return (rcu_load (&node->next));
}

/*
 * Add a node between two nodes.
 *
 * This function is private.
 */
static inline void
list_rcu_add (struct list *prev, struct list *next, struct list *node)
{
  node->next = next;
  node->prev = prev;
  rcu_store (&prev->next, node);
  next->prev = node;
}

// Insert a node at the head of a list.
static inline void
list_rcu_insert_head (struct list *list, struct list *node)
{
  list_rcu_add (list, list->next, node);
}

// Insert a node at the tail of a list.
static inline void
list_rcu_insert_tail (struct list *list, struct list *node)
{
  list_rcu_add (list->prev, list, node);
}

// Insert a node before another node.
static inline void
list_rcu_insert_before (struct list *node, struct list *next)
{
  list_rcu_add (next->prev, next, node);
}

// Insert a node after another node.
static inline void
list_rcu_insert_after (struct list *node, struct list *prev)
{
  list_rcu_add (prev, prev->next, node);
}

/*
 * Remove a node from a list.
 *
 * After completion, the node is stale.
 */
static inline void
list_rcu_remove (struct list *node)
{
  node->next->prev = node->prev;
  rcu_store (&node->prev->next, node->next);
}

/*
 * Macro that evaluates to the address of the structure containing the
 * given node based on the given type and member.
 */
#define list_rcu_entry(node, type, member)   \
  structof (rcu_load (&(node)), type, member)

/*
 * Get the first entry of a list.
 *
 * Unlike list_first_entry(), this macro may evaluate to NULL, because
 * the node pointer can only be read once, preventing the combination
 * of lockless list_empty()/list_first_entry() variants.
 */
#define list_rcu_first_entry(head, type, member)   \
MACRO_BEGIN   \
  \
  struct list *list_ = (head), *first_ = list_rcu_first (list_);   \
  list_end (list_, first_) ? NULL : list_entry (first_, type, member);   \
MACRO_END

/*
 * Get the entry next to the given entry.
 *
 * Unlike list_next_entry(), this macro may evaluate to NULL, because
 * the node pointer can only be read once, preventing the combination
 * of lockless list_empty()/list_next_entry() variants.
 */
#define list_rcu_next_entry(head, entry, member)            \
MACRO_BEGIN                                                 \
  struct list *list_ = (head), *next_ = list_rcu_next (&entry->member);   \
  list_end (list_, next_) ?   \
    NULL : list_entry (next_, typeof (*entry), member);   \
MACRO_END

/*
 * Forge a loop to process all nodes of a list.
 *
 * The node must not be altered during the loop.
 */
#define list_rcu_for_each(lst, node)   \
  for (struct list *node = list_rcu_first (lst);   \
       !list_end (lst, node);   \
       node = list_rcu_next (node))

/*
 * Forge a loop to process all entries of a list.
 *
 * The entry node must not be altered during the loop.
 */
#define list_rcu_for_each_entry(list, entry, member)   \
  for (entry = list_rcu_first_entry (list, typeof (*entry), member);   \
       entry != NULL;   \
       entry = list_rcu_next_entry (list, entry, member))

#endif
