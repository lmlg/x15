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
#include <kern/slist.h>
#include <kern/spinlock.h>
#include <kern/xcall.h>

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

static struct vm_rset_entry*
vm_rset_entry_create (void *pte, uintptr_t va, uint32_t cpu)
{
  struct vm_rset_entry *ret = kmem_cache_alloc (&vm_rset_cache);
  if (! ret)
    return (ret);

  work_init (&ret->work, vm_rset_entry_fini);
  ret->pte = pte;
  ret->va = va;
  ret->cpu = cpu;
  return (ret);
}

int
vm_rset_page_link (struct vm_page *page, void *pte, uintptr_t va, uint32_t cpu)
{
  _Auto entry = vm_rset_entry_create (pte, va, cpu);
  if (! entry)
    return (ENOMEM);

  spinlock_lock (&page->rset_lock);
  slist_rcu_insert_tail (&page->rset, &entry->link);
  spinlock_unlock (&page->rset_lock);
  vm_page_mark_dirty (page);
  return (0);
}

void
vm_rset_del (struct vm_page *page, void *pte)
{
  struct slist_node *prev = NULL;
  struct vm_rset_entry *entry;

  SPINLOCK_GUARD (&page->rset_lock);
  slist_rcu_for_each_entry (&page->rset, entry, link)
    {
      if (pte != entry->pte)
        {
          prev = &entry->link;
          continue;
        }

      slist_rcu_remove (&page->rset, prev);
      entry->cpu = ~0u;
      rcu_defer (&entry->work);
      return;
    }
}

void
vm_rset_mark_ro (struct vm_page *page)
{
  struct pmap_clean_data cdata = { .pa = vm_page_to_pa (page) };
  struct vm_rset_entry *entry;
  slist_rcu_for_each_entry (&page->rset, entry, link)
    {
      cdata.va = entry->va;
      cdata.pte = entry->pte;

      thread_pin ();
      if ((cdata.cpu = entry->cpu) == cpu_id ())
        {
          pmap_xcall_clean (&cdata);
          thread_unpin ();
        }
      else if (cdata.cpu != ~0u)
        {
          thread_unpin ();
          xcall_call (pmap_xcall_clean, &cdata, cdata.cpu);
        }
    }
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
