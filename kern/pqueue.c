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
 */

#include <kern/pqueue.h>

void
pqueue_insert (struct pqueue *pq, struct pqueue_node *node)
{
  struct pqueue_node *head = pq->head;

  if (! head)
    { // Empty queue.
      node->prev = node->next = node;
      pq->head = node;
    }
  else if (head->prio < node->prio)
    { // New node becomes the top.
      node->prev = head->prev;
      node->next = head;
      node->prev->next = node;
      node->next->prev = node;
      node->next->prio = node->prio - node->next->prio;
      pq->head = node;
    }
  else
    { // Find insertion point.
      uint32_t prio = head->prio;
      while (prio - head->next->prio >= node->prio && head->next != pq->head)
        {
          head = head->next;
          prio -= head->prio;
        }

      node->prev = head;
      node->next = head->next;
      node->prev->next = node;
      node->next->prev = node;
      node->prio = prio - node->prio;
      if (node->next != pq->head)
        node->next->prio -= node->prio;
    }
}

struct pqueue_node*
pqueue_pop (struct pqueue *pq)
{
  struct pqueue_node *node = pq->head;
  if (! node)
    return (node);   // Empty queue.
  else if (node->next == node)
    { // Remove last element.
      pq->head = NULL;
      return (node);
    }

  node->prev->next = node->next;
  node->next->prev = node->prev;
  node->next->prio = node->prio - node->next->prio;
  pq->head = node->next;

  return (node);
}

void
pqueue_remove (struct pqueue *pq, struct pqueue_node *node)
{
  if (!pq->head)
    return;
  else if (pq->head != node)
    {
      node->prev->next = node->next;
      node->next->prev = node->prev;
      if (node->next != pq->head)
        node->next->prio += node->prio;
    }
  else if (node->next == node)
    { // Single element queue.
      node->next = node->prev = NULL;
      pq->head = NULL;
    }
  else
    {
      node->prev->next = node->next;
      node->next->prev = node->prev;
      node->next->prio = node->prio - node->next->prio;
      pq->head = node->next;
    }
}
