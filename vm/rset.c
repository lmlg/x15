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

#include <kern/atomic.h>
#include <kern/kmem.h>
#include <kern/spinlock.h>

#include <machine/cpu.h>
#include <machine/pmap.h>

#include <vm/page.h>
#include <vm/rset.h>

static struct kmem_cache vm_rset_cache;

static void
vm_rset_entry_fini (struct work *wp)
{
  kmem_cache_free (&vm_rset_cache, structof (wp, struct vm_rset_entry, work));
}

struct vm_rset_entry*
vm_rset_entry_create (void *pte)
{
  struct vm_rset_entry *ret = kmem_cache_alloc (&vm_rset_cache);
  if (ret)
    work_init (&ret->work, vm_rset_entry_fini);

  ret->pte = pte;
  return (ret);
}

int
vm_rset_page_link (struct vm_page *page, void *pte)
{
  _Auto entry = vm_rset_entry_create (pte);
  if (! entry)
    return (ENOMEM);

  SPINLOCK_GUARD (&page->rset_lock);
  list_rcu_insert_tail (&page->node, &entry->link);
  return (0);
}

void
vm_rset_del (struct vm_page *page, void *pte)
{
  struct vm_rset_entry *entry;
  list_rcu_for_each_entry (&page->node, entry, link)
    if (pte == entry->pte)
      {
        list_rcu_remove (&entry->link);
        if (pmap_pte_isdirty (pte))
          page->dirty = 1;

        rcu_defer (&entry->work);
        return;
      }
}

static uintptr_t
vm_rset_cas (uintptr_t *ptr, uintptr_t bits)
{
  while (1)
    {
      uintptr_t prev = *ptr;
      if (!(prev & bits))
        return (0);
      else if (atomic_cas_bool (ptr, prev, prev & ~bits, ATOMIC_ACQ_REL))
        return (prev);

      cpu_pause ();
    }
}

uintptr_t
vm_rset_clr (struct list *list, uintptr_t bits)
{
  RCU_GUARD ();

  uintptr_t acc = 0;
  struct vm_rset_entry *entry;
  list_rcu_for_each_entry (list, entry, link)
    acc |= vm_rset_cas (entry->pte, bits);

  return (acc);
}

static int __init
vm_rset_setup (void)
{
  kmem_cache_init (&vm_rset_cache, "vm_rset_entry",
                   sizeof (struct vm_rset_entry), 0, NULL, 0);
  return (0);
}

INIT_OP_DEFINE (vm_rset_setup,
                INIT_OP_DEP (kmem_setup, true));
