/*
 * Copyright (c) 2023 Agustina Arzille.
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
 * Adjustable priority queue.
 *
 * Unlike the standard priority list bundled in the kernel, this data
 * structure can increase the priority of every member in O(1) time.
 * For this reason, its usage is encouraged when starvation needs to
 * be avoided.
 */

#ifndef KERN_PQUEUE_H
#define KERN_PQUEUE_H

#include <stdbool.h>
#include <stdint.h>

#include <kern/macros.h>

/*
 * Priority queue node.
 *
 * Note that the 'priority' member is not really meaningful to clients,
 * as it's dynamically adjusted as the queue is modified.
 */
struct pqueue_node
{
  struct pqueue_node *prev;
  struct pqueue_node *next;
  uint32_t prio;
};

struct pqueue
{
  struct pqueue_node *head;
};

static inline void
pqueue_init (struct pqueue *pq)
{
  pq->head = NULL;
}

static inline void
pqueue_node_init (struct pqueue_node *node, uint32_t prio)
{
  node->prev = node->next = NULL;
  node->prio = prio;
}

static inline bool
pqueue_node_unlinked (const struct pqueue_node *node)
{
  return (node->next == NULL && node->prev == NULL);
}

static inline bool
pqueue_empty (const struct pqueue *pqueue)
{
  return (pqueue->head == NULL);
}

static inline uint32_t
pqueue_node_prio (const struct pqueue_node *pnode)
{
  return (pnode->prio);
}

// Insert a node in the priority queue.
void pqueue_insert (struct pqueue *pqueue, struct pqueue_node *node);

/*
 * Pop a node from the priority list, returning the top-most one,
 * or NULL if empty.
 */
struct pqueue_node* pqueue_pop (struct pqueue *pqueue);

// Remove a node from the queue.
void pqueue_remove (struct pqueue *pqueue, struct pqueue_node *node);

// Increment the priority of all nodes in the queue.
static inline void
pqueue_inc (struct pqueue *pqueue, uint32_t off)
{
  if (!pqueue->head)
    return;

  _Auto head = pqueue->head;
  if (likely (head->prio < UINT32_MAX - off))
    head->prio += off;
  else
    head->prio = UINT32_MAX;
}

static inline struct pqueue_node*
pqueue_node_next (const struct pqueue *pqueue, struct pqueue_node *node)
{
  return (!node || node->next == pqueue->head ? NULL : node->next);
}

#define pqueue_entry   structof

#define pqueue_first_entry(pq, type, member)   \
  ({   \
     _Auto pq_ = (pq);   \
     pqueue_empty (pq_) ? NULL : pqueue_entry (pq_->head, type, member);   \
   })

#define pqueue_pop_entry(pq, type, member)   \
  pqueue_entry (pqueue_pop (pq), type, member)

#define pqueue_next_entry(pq, node, type, member)   \
  ({   \
     _Auto nxt_ = pqueue_node_next ((pq), (node));   \
     nxt_ ? pqueue_entry (nxt_, type, member) : NULL;   \
   })

#define pqueue_for_each(pq, node)   \
  for (struct pqueue_node *node = (pq)->head;   \
       node != NULL; node = pqueue_node_next ((pq), node))

#define pqueue_for_each_safe(pq, node, aux)   \
  for (struct pqueue_node *node = (pq)->head,   \
       *aux = pqueue_node_next ((pq), node);   \
       node != NULL; node = aux, aux = pqueue_node_next ((pq), aux))

#define pqueue_for_each_entry(pq, entry, member)   \
  for (entry = pqueue_first_entry ((pq), typeof (*entry), member);   \
       entry != NULL;   \
       entry = pqueue_next_entry ((pq), entry, typeof (*entry), member))

#define pqueue_for_each_entry_safe(pq, entry, aux, member)   \
  for (entry = pqueue_first_entry ((pq), typeof (*entry), member),   \
       aux = entry ? pqueue_next_entry (pq, &entry->member,   \
                                        typeof (*entry), member) : NULL;   \
       entry != NULL; entry = aux,   \
       aux = !entry ? NULL :   \
             pqueue_next_entry ((pq), &aux->member, typeof (*aux), member))


#endif
