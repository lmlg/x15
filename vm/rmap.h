/*
 * Copyright (c) 2024 Agustina Arzille.
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
 * Reverse mappings.
 *
 * These maps contain all the virtual -> physical translations that
 * exist for a specific page. They allow users to know whether a page
 * is dirty or has been recently accesed, for instance.
 */

#ifndef VM_RMAP_H
#define VM_RMAP_H

#include <stdint.h>

#include <kern/init.h>
#include <kern/list.h>
#include <kern/work.h>

struct vm_rmap_entry
{
  struct list link;
  struct work work;
  void *pte;
};

struct vm_page;

// Allocate a new RMAP entry.
struct vm_rmap_entry* vm_rmap_entry_create (void);

// Add a new RMAP entry to a list. The caller is responsible for any locking.
static inline void
vm_rmap_add (struct list *list, struct vm_rmap_entry *entry, void *pte)
{
  entry->pte = pte;
  list_rcu_insert_tail (list, &entry->link);
}

// Link a page to a PTE.
int vm_rmap_page_link (struct vm_page *page, void *pte);

/*
 * Remove an RMAP corresponding to a PTE.
 * The caller is responsible for any locking.
 */
void vm_rmap_del (struct list *list, void *pte);

/*
 * Traverse the RMAP entries in a list, testing for the presence of, and
 * clearing the specified bits. Returns true if any of the bits were present.
 */
bool vm_rmap_test_clr (struct list *list, uintptr_t bits);

/*
 * This init operation provides :
 *  - module fully initialized
 */
INIT_OP_DECLARE (vm_rmap_setup);

#endif
