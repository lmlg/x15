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
 */

#include <kern/kmem.h>
#include <kern/spinlock.h>

#include <machine/pmap.h>

#include <vm/page.h>
#include <vm/rmap.h>

static struct kmem_cache vm_rmap_cache;

static void
vm_rmap_entry_fini (struct work *wp)
{
  kmem_cache_free (&vm_rmap_cache, structof (wp, struct vm_rmap_entry, work));
}

struct vm_rmap_entry*
vm_rmap_entry_create (void)
{
  struct vm_rmap_entry *ret = kmem_cache_alloc (&vm_rmap_cache);
  if (ret)
    work_init (&ret->work, vm_rmap_entry_fini);

  return (ret);
}

int
vm_rmap_page_link (struct vm_page *page, void *pte)
{
  _Auto entry = vm_rmap_entry_create ();
  if (! entry)
    return (ENOMEM);

  SPINLOCK_GUARD (&page->rmap_lock);
  vm_rmap_add (&page->node, entry, pte);
  return (0);
}

void
vm_rmap_del (struct list *list, void *pte)
{
  struct vm_rmap_entry *entry;
  list_rcu_for_each_entry (list, entry, link)
    if (pte == entry->pte)
      {
        list_rcu_remove (&entry->link);
        rcu_defer (&entry->work);
        return;
      }
}

bool
vm_rmap_test_clr (struct list *list, uintptr_t bits)
{
  RCU_GUARD ();

  phys_addr_t acc = 0;
  struct vm_rmap_entry *entry;
  list_rcu_for_each_entry (list, entry, link)
    {
      acc |= *(phys_addr_t *)entry->pte;
      *(phys_addr_t *)entry->pte &= ~bits;
    }

  return ((acc & bits) != 0);
}

static int __init
vm_rmap_setup (void)
{
  kmem_cache_init (&vm_rmap_cache, "vm_rmap_entry",
                   sizeof (struct vm_rmap_entry), 0, NULL, 0);
  return (0);
}

INIT_OP_DEFINE (vm_rmap_setup,
                INIT_OP_DEP (kmem_setup, true));
