/*
 * Copyright (c) 2017 Richard Braun.
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
 * Singly-linked list.
 */

#ifndef KERN_SLIST_H
#define KERN_SLIST_H

#include <stdbool.h>
#include <stddef.h>

#include <kern/macros.h>
#include <kern/rcu.h>
#include <kern/slist_types.h>

struct slist;

struct slist_node;

// Static list initializer.
#define SLIST_INITIALIZER(list)   { NULL, NULL }

// Initialize a list.
static inline void
slist_init (struct slist *list)
{
  list->first = list->last = NULL;
}

// Initialize a list node.
static inline void
slist_node_init (struct slist_node *node)
{
  node->next = NULL;
}

// Return the first node of a list.
static inline struct slist_node*
slist_first (const struct slist *list)
{
  return (list->first);
}

// Return the last node of a list.
static inline struct slist_node*
slist_last (const struct slist *list)
{
  return (list->last);
}

// Return the node next to the given node.
static inline struct slist_node*
slist_next (const struct slist_node *node)
{
  return (node->next);
}

// Return true if node is invalid and denotes one of the ends of the list.
static inline bool
slist_end (const struct slist_node *node)
{
  return (node == NULL);
}

/*
 * Return true if list is empty.
 */
static inline bool
slist_empty (const struct slist *list)
{
  return (list->first == NULL);
}

// Return true if list contains exactly one node.
static inline bool
slist_singular (const struct slist *list)
{
  return (!slist_empty (list) && list->first == list->last);
}

/*
 * Append the nodes of list2 at the end of list1.
 *
 * After completion, list2 is stale.
 */
static inline void
slist_concat (struct slist *list1, const struct slist *list2)
{
  if (slist_empty (list2))
    return;
  else if (slist_empty (list1))
    list1->first = list2->first;
  else
    list1->last->next = list2->first;

  list1->last = list2->last;
}

/*
 * Set the new head of a list.
 *
 * This function is an optimized version of :
 * list_init(&new_list);
 * list_concat(&new_list, &old_list);
 */
static inline void
slist_set_head (struct slist *new_head, const struct slist *old_head)
{
  *new_head = *old_head;
}

// Insert a node at the head of a list.
static inline void
slist_insert_head (struct slist *list, struct slist_node *node)
{
  if (slist_empty (list))
    list->last = node;

  node->next = list->first;
  list->first = node;
}

// Insert a node at the tail of a list.
static inline void
slist_insert_tail (struct slist *list, struct slist_node *node)
{
  node->next = NULL;

  if (slist_empty (list))
    list->first = node;
  else
    list->last->next = node;

  list->last = node;
}

/*
 * Insert a node after another node.
 *
 * The prev node must be valid.
 */
static inline void
slist_insert_after (struct slist *list, struct slist_node *node,
                    struct slist_node *prev)
{
  node->next = prev->next;
  prev->next = node;

  if (list->last == prev)
    list->last = node;
}

/*
 * Remove a node from a list.
 *
 * The prev argument must point to the node immediately preceding the target
 * node. It may safely denote the end of the given list (NULL), in which case
 * the first node is removed.
 */
static inline void
slist_remove (struct slist *list, struct slist_node *prev)
{
  struct slist_node *node;

  if (slist_end (prev))
    {
      node = list->first;
      list->first = node->next;

      if (list->last == node)
        list->last = NULL;
    }
  else
    {
      node = prev->next;
      prev->next = node->next;

      if (list->last == node)
        list->last = prev;
    }
}

/*
 * Macro that evaluates to the address of the structure containing the
 * given node based on the given type and member.
 */
#define slist_entry(node, type, member)   structof (node, type, member)

// Get the first entry of a list.
#define slist_first_entry(list, type, member)   \
MACRO_BEGIN   \
  struct slist_node *first_ = (list)->first;   \
  slist_end (first_) ? NULL : slist_entry (first_, type, member);   \
MACRO_END

// Get the last entry of a list.
#define slist_last_entry(list, type, member)   \
MACRO_BEGIN   \
  struct slist_node *last_ = (list)->last;   \
  slist_end (last_) ? NULL : slist_entry(last_, type, member);   \
MACRO_END

// Get the entry next to the given entry.
#define slist_next_entry(entry, member)   \
MACRO_BEGIN   \
  struct slist_node *next_ = (entry)->member.next;   \
  slist_end (next_) ?   \
    NULL : slist_entry(next_, typeof(*entry), member);   \
MACRO_END

/*
 * Forge a loop to process all nodes of a list.
 *
 * The node must not be altered during the loop.
 */
#define slist_for_each(list, node)   \
  for (_Auto node = slist_first (list);   \
       !slist_end (node);   \
       node = slist_next (node))

// Forge a loop to process all nodes of a list.
#define slist_for_each_safe(list, node, tmp)   \
  for (node = slist_first (list),   \
       tmp = slist_end (node) ? NULL : slist_next (node);   \
       !slist_end (node);   \
       node = tmp,   \
       tmp = slist_end (node) ? NULL : slist_next (node))

/*
 * Forge a loop to process all entries of a list.
 *
 * The entry node must not be altered during the loop.
 */
#define slist_for_each_entry(list, entry, member)   \
  for (entry = slist_first_entry (list, typeof (*entry), member);   \
       entry != NULL;   \
       entry = slist_next_entry (entry, member))

// Forge a loop to process all entries of a list.
#define slist_for_each_entry_safe(list, entry, tmp, member)   \
  for (entry = slist_first_entry (list, typeof(*entry), member),   \
       tmp = entry ? slist_next_entry (entry, member) : NULL;   \
       entry != NULL;   \
       entry = tmp,   \
       tmp = entry ? slist_next_entry (entry, member) : NULL)

/*
 * Lockless variants
 *
 * The slist_end() function may be used from read-side critical sections.
 */

/*
 * Return the first node of a list.
 */
static inline struct slist_node*
slist_rcu_first (const struct slist *list)
{
  return (rcu_load (&list->first));
}

/*
 * Return the node next to the given node.
 */
static inline struct slist_node*
slist_rcu_next (const struct slist_node *node)
{
  return (rcu_load (&node->next));
}

/*
 * Insert a node at the head of a list.
 */
static inline void
slist_rcu_insert_head (struct slist *list, struct slist_node *node)
{
  if (slist_empty (list))
    list->last = node;

  node->next = list->first;
  rcu_store (&list->first, node);
}

// Insert a node at the tail of a list.
static inline void
slist_rcu_insert_tail (struct slist *list, struct slist_node *node)
{
  node->next = NULL;
  rcu_store (slist_empty (list) ? &list->first : &list->last->next, node);
  list->last = node;
}

/*
 * Insert a node after another node.
 *
 * The prev node must be valid.
 */
static inline void
slist_rcu_insert_after (struct slist *list, struct slist_node *node,
                        struct slist_node *prev)
{
  node->next = prev->next;
  rcu_store (&prev->next, node);

  if (list->last == prev)
    list->last = node;
}

/*
 * Remove a node from a list.
 *
 * The prev argument must point to the node immediately preceding the target
 * node. It may safely denote the end of the given list, in which case the
 * first node is removed.
 */
static inline void
slist_rcu_remove (struct slist *list, struct slist_node *prev)
{
  if (slist_end (prev))
    {
      _Auto node = list->first;
      rcu_store (&list->first, node->next);

      if (list->last == node)
        list->last = NULL;
    }
  else
    {
      _Auto node = prev->next;
      rcu_store (&prev->next, node->next);

      if (list->last == node)
        list->last = prev;
    }
}

/*
 * Macro that evaluates to the address of the structure containing the
 * given node based on the given type and member.
 */
#define slist_rcu_entry(node, type, member)   \
  structof(rcu_load (&(node)), type, member)

// Get the first entry of a list.
#define slist_rcu_first_entry(list, type, member)   \
MACRO_BEGIN   \
  struct slist_node *first_ = slist_rcu_first (list);   \
  slist_end (first_) ? NULL : slist_entry (first_, type, member);   \
MACRO_END

// Get the entry next to the given entry.
#define slist_rcu_next_entry(entry, member)   \
MACRO_BEGIN   \
  struct slist_node *next_ = slist_rcu_next (&entry->member);   \
  slist_end (next_) ?   \
    NULL : slist_entry (next_, typeof (*entry), member);   \
MACRO_END

// Forge a loop to process all nodes of a list.
#define slist_rcu_for_each(list, node)   \
  for (_Auto node = slist_rcu_first (list);          \
       !slist_end (node);                      \
       node = slist_rcu_next (node))

// Forge a loop to process all entries of a list.
#define slist_rcu_for_each_entry(list, entry, member)   \
  for (entry = slist_rcu_first_entry (list, typeof (*entry), member);   \
       entry != NULL;   \
       entry = slist_rcu_next_entry (entry, member))

#endif
