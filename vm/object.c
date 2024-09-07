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
 *
 * This implementation is based on the paper "A lockless pagecache in Linux"
 * by Nick Piggin. It allows looking up pages without contention on VM objects.
 */

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include <kern/capability.h>
#include <kern/hash.h>
#include <kern/init.h>
#include <kern/kmem.h>
#include <kern/list.h>
#include <kern/log2.h>
#include <kern/mutex.h>
#include <kern/rcu.h>
#include <kern/unwind.h>
#include <kern/user.h>

#include <vm/object.h>
#include <vm/page.h>
#include <vm/rset.h>

#include <machine/page.h>

struct vm_object vm_object_kernel_object;
static struct kmem_cache vm_object_cache;

struct vm_object_copy_data
{
  uintptr_t va;
  struct thread_pmap_data *pte;
  struct vm_page *page;
  int washed;
};

static int __init
vm_object_bootstrap (void)
{
  return (0);
}

INIT_OP_DEFINE (vm_object_bootstrap,
                INIT_OP_DEP (mutex_setup, true),
                INIT_OP_DEP (rdxtree_setup, true),
                INIT_OP_DEP (vm_page_setup, true));

static int __init
vm_object_setup (void)
{
  kmem_cache_init (&vm_object_cache, "vm_object",
                   sizeof (struct vm_object), 0, NULL, 0);
  return (0);
}

INIT_OP_DEFINE (vm_object_setup,
                INIT_OP_DEP (kmem_setup, true));

void __init
vm_object_init (struct vm_object *object, uint32_t flags, void *ctx)
{
  mutex_init (&object->lock);
  rdxtree_init (&object->pages, RDXTREE_ALLOC_SLEEP);
  object->nr_pages = 0;
  object->refcount = 1;
  object->flags = flags;

  if (flags & VM_OBJECT_EXTERNAL)
    object->channel = (struct cap_channel *)ctx;
  else
    object->page_get = (typeof (object->page_get))ctx;
}

int
vm_object_create (struct vm_object **objp, uint32_t flags, void *ctx)
{
  struct vm_object *ret = kmem_cache_alloc (&vm_object_cache);
  if (! ret)
    return (ENOMEM);

  vm_object_init (ret, flags, ctx);
  *objp = ret;
  return (0);
}

static void
vm_object_work_fini (struct work *work)
{
  kmem_cache_free (&vm_object_cache, structof (work, struct vm_object, work));
}

void
vm_object_destroy (struct vm_object *object)
{
  assert (object->nr_pages == 0);
  rdxtree_remove_all (&object->pages);
  if (object->flags & VM_OBJECT_EXTERNAL)
    cap_base_rel (object->channel);

  work_init (&object->work, vm_object_work_fini);
  rcu_defer (&object->work);
}

int
vm_object_swap (struct vm_object *object, struct vm_page *page,
                uint64_t offset, struct vm_page *expected)
{
  assert (vm_page_aligned (offset));
  assert (vm_page_referenced (page));
  if (!atomic_cas_bool_acq (&page->object, NULL, object))
    // Page belongs to a different object.
    return (EAGAIN);

  mutex_lock (&object->lock);

  struct vm_page *prev = NULL;
  void **slot;
  int error = rdxtree_insert_slot (&object->pages, vm_page_btop (offset),
                                   page, &slot);

  if (error)
    {
      if (error != EBUSY || atomic_load_rlx (slot) != expected)
        goto skip;

      /*
       * Replace the page slot. Also, if this is the page's last
       * reference, free it after the critical section.
       */

      prev = rdxtree_replace_slot (slot, page);
      if (!vm_page_unref_nofree (prev))
        prev = NULL;
    }

  page->offset = offset;
  ++object->nr_pages;
  assert (object->nr_pages != 0);
  vm_object_ref (object);

  mutex_unlock (&object->lock);
  if (prev)
    vm_page_free (prev, 0, VM_PAGE_SLEEP);

  return (0);

skip:
  mutex_unlock (&object->lock);
  return (error);
}

void
vm_object_remove (struct vm_object *object, uint64_t start, uint64_t end)
{
  assert (vm_page_aligned (start));
  assert (vm_page_aligned (end));
  assert (start <= end);

  struct list pages;
  list_init (&pages);

  uint32_t cnt = 0;

  {
    MUTEX_GUARD (&object->lock);
    for (uint64_t offset = start; offset < end; offset += PAGE_SIZE)
      {
        void *node;
        int idx;
        void **slot = rdxtree_lookup_common (&object->pages,
                                             vm_page_btop (offset), true,
                                             &node, &idx);
        if (! slot)
          continue;

        struct vm_page *page = atomic_load_rlx (slot);
        if (!vm_page_unref_nofree (page) ||
            (page->dirty && (object->flags & VM_OBJECT_FLUSHES)))
          continue;

        rdxtree_remove_node_idx (&object->pages, slot, node, idx);
        vm_page_unlink (page);
        list_insert_tail (&pages, &page->node);
        assert (object->nr_pages != 0);
        ++cnt;
      }

    object->nr_pages -= cnt;
  }

  vm_object_unref_many (object, cnt);
  vm_page_list_free (&pages);
}

void
vm_object_detach (struct vm_object *object, struct vm_page *page)
{
  MUTEX_GUARD (&object->lock);
  void *node;
  int idx;
  void **slot = rdxtree_lookup_common (&object->pages,
                                       vm_page_btop (page->offset), true,
                                       &node, &idx);

  if (!slot || atomic_load_rlx (slot) != page)
    return;

  rdxtree_remove_node_idx (&object->pages, slot, node, idx);
  --object->nr_pages;
  vm_object_unref (object);
}

struct vm_page*
vm_object_lookup (struct vm_object *object, uint64_t offset)
{
  RCU_GUARD ();
  while (1)
    {
      struct vm_page *page = rdxtree_lookup (&object->pages,
                                             vm_page_btop (offset));
      if (!page || vm_page_tryref (page) == 0)
        return (page);
    }
}

static int
vm_object_anon_pager_get (struct vm_object *ap __unused, uint64_t off __unused,
                          size_t size, int prot __unused, void *dst)
{
  memset (dst, 0, size);
  return (size >> PAGE_SHIFT);
}

int
vm_object_anon_create (struct vm_object **outp)
{
  return (vm_object_create (outp, 0, vm_object_anon_pager_get));
}

ssize_t
vm_object_list_dirty (struct vm_object *obj, struct cap_page_info *upg)
{
  if (!user_check_range (upg, sizeof (*upg)))
    return (-EFAULT);

  struct unw_fixup fixup;
  int error = unw_fixup_save (&fixup);

  if (unlikely (error))
    {
      rcu_read_leave ();
      return (-error);
    }

  struct cap_page_info pg = *upg;
  void *out = pg.offsets;
  uint32_t cnt = pg.offset_cnt;

  if (! cnt)
    return (0);
  else if (!user_check_range (out, cnt * sizeof (uint64_t)))
    return (-EFAULT);

  struct rdxtree_iter it;
  struct vm_page *page;

  rcu_read_enter ();
  rdxtree_for_each (&obj->pages, &it, page)
    {
      if (page->dirty == VM_PAGE_CLEAN)
        continue;

      ((union user_ua *)out)->u8 = page->offset;
      if (--cnt == 0)
        break;

      out = (char *)out + sizeof (uint64_t);
    }

  rcu_read_leave ();
  return ((ssize_t)(pg.offset_cnt - cnt));
}

static void
vm_object_copy_data_fini (struct vm_object_copy_data *dp, int err)
{
  if (dp->pte)
    {
      pmap_ipc_pte_put (dp->pte);
      thread_unpin ();
      dp->pte = NULL;
    }

  if (dp->washed && !err)
    vm_page_wash_end (dp->page);

  vm_page_unref (dp->page);
}

static ssize_t
vm_object_copy_single_page (struct vm_object_copy_data *dp,
                            struct ipc_iov_iter *it, struct iovec *iov)
{
  dp->washed = 0;
  if (dp->page->dirty != VM_PAGE_CLEAN)
    {  // Begin the page laundering process and mark it as read-only.
      vm_page_wash_begin (dp->page);
      vm_rset_mark_ro (dp->page);
      dp->washed = 1;
    }

  // Get the special PTE to perform the copy.
  thread_pin ();
  dp->pte = pmap_ipc_pte_get_idx (2);
  pmap_ipc_pte_set (dp->pte, dp->va, vm_page_to_pa (dp->page));

  const char *src = (const void *)dp->va;
  ssize_t ret = 0;

  // Copy the page into the user buffer.
  while (1)
    {
      ssize_t tmp = MIN (PAGE_SIZE - ret, (ssize_t)iov->iov_len);
      memcpy (iov->iov_base, src, tmp);
      src += tmp, ret += tmp;
      iovec_adv (iov, tmp);

      if (ret == PAGE_SIZE)
        break;

      iov = ipc_iov_iter_usrnext (it, true, &ret);
      if (! iov)
        break;
    }

  // Cleanup.
  vm_object_copy_data_fini (dp, ret < 0);
  return (ret);
}

ssize_t
vm_object_copy_pages (struct vm_object *obj, struct cap_page_info *upg)
{
  if (!user_check_range (upg, sizeof (*upg)))
    return (-EFAULT);

  struct vm_object_copy_data data = { .pte = NULL, .page = NULL };
  struct unw_fixup fixup;
  int error = unw_fixup_save (&fixup);

  if (unlikely (error))
    {
      vm_object_copy_data_fini (&data, 1);
      return (-error);
    }

  struct cap_page_info pg = *upg;
  void *offs = pg.offsets;

  if (!user_check_range (offs, pg.offset_cnt * sizeof (uint64_t)) ||
      !P2ALIGNED ((uintptr_t)pg.iovs, alignof (struct iovec)))
    return (-EFAULT);

  ssize_t ret = 0;
  data.va = vm_map_ipc_addr ();

  struct ipc_iov_iter it;
  ipc_iov_iter_init (&it, pg.iovs, pg.iov_cnt);

  for (uint32_t i = 0; i < pg.offset_cnt; ++i)
    {
      _Auto uptr = (union user_ua *)offs;
      uint64_t offset = uptr->u8;
      data.page = vm_object_lookup (obj, offset);
      offs = (char *)offs + sizeof (uint64_t);

      _Auto dv = ipc_iov_iter_usrnext (&it, true, &ret);

      if (! data.page)
        {
          uptr->u8 = offset | 1;
          if ((pg.flags & CAP_PAGES_ADV_SKIP) && dv)
            iovec_adv (dv, MIN (PAGE_SIZE, dv->iov_len));

          continue;
        }
      else if (! dv)
        break;

      ssize_t tmp = vm_object_copy_single_page (&data, &it, dv);
      if (tmp < 0)
        return (tmp);

      ret += tmp;
    }

  return (ret);
}

int
vm_object_map_dirty (struct vm_object *obj, struct cap_page_info *upg)
{
  if (!user_check_range (upg, sizeof (*upg)))
    return (-EFAULT);

  struct unw_fixup fixup;
  int error = unw_fixup_save (&fixup);
  if (unlikely (error))
    {
      rcu_read_leave ();
      return (-error);
    }

  _Auto pg = *upg;
  if (!pg.offset_cnt ||
      !user_check_range (pg.offsets, pg.offset_cnt * sizeof (uint64_t)))
    return (pg.offset_cnt ? -EFAULT : 0);

  struct rdxtree_iter it;
  struct vm_page *page;
  int ret = 0;
  void *out = pg.offsets;
  uint32_t cnt = pg.offset_cnt;
  uint64_t first = 1, last;

  rcu_read_enter ();
  rdxtree_for_each (&obj->pages, &it, page)
    {
      if (page->dirty != VM_PAGE_DIRTY)
        continue;
      else if (--cnt == (uint32_t)-1)
        {
          pg.flags |= CAP_PAGES_MORE;
          break;
        }

      ((union user_ua *)out)->u8 = page->offset;
      out = (char *)out + sizeof (uint64_t);

      if (first == 1)
        first = page->offset;

      last = page->offset;
      vm_page_wash_begin (page);
      vm_rset_mark_ro (page);
      ++ret;
    }

  rcu_read_leave ();
  if (! ret)
    return (ret);

  int map_flags = VM_MAP_FLAGS (VM_PROT_READ, VM_PROT_READ, VM_INHERIT_NONE,
                                VM_ADV_DEFAULT, VM_MAP_CLEAN);
  pg.vme.size = (size_t)(last - first) + PAGE_SIZE;
  pg.vme.prot = pg.vme.max_prot = VM_PROT_READ;
  int rv = vm_map_enter (vm_map_self (), &pg.vme.addr, pg.vme.size,
                         map_flags, obj, first);

  if (rv != 0 || (rv = user_copy_to (upg, &pg, sizeof (pg))) != 0)
    ret = -rv;

  return (ret);
}
