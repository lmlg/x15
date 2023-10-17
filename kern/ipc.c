/*
 * Copyright (c) 2022 Agustina Arzille.
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
 */

#include <kern/capability.h>
#include <kern/cspace.h>
#include <kern/ipc.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/unwind.h>
#include <kern/user.h>

#include <machine/cpu.h>

#include <vm/map.h>
#include <vm/page.h>

struct ipc_data
{
  cpu_flags_t cpu_flags;
  uintptr_t va;
  int direction;
  int prot;
  void *ipc_pte;
  phys_addr_t prev;
  struct vm_page *page;
};

static void
ipc_data_init (struct ipc_data *data, int direction)
{
  data->direction = direction;
  data->prot = direction == IPC_COPY_FROM ? VM_PROT_READ : VM_PROT_RDWR;
  data->va = vm_map_ipc_addr ();
  data->ipc_pte = NULL;
  data->page = NULL;
}

static void
ipc_data_intr_save (struct ipc_data *data)
{
  cpu_intr_save (&data->cpu_flags);
}

static void
ipc_data_intr_restore (struct ipc_data *data)
{
  cpu_intr_restore (data->cpu_flags);
}

static void
ipc_data_page_ref (struct ipc_data *data, phys_addr_t pa)
{
  assert (!data->page);
  struct vm_page *page = vm_page_lookup (pa);
  assert (page);
  vm_page_ref (page);
  data->page = page;
}

static void
ipc_data_page_unref (struct ipc_data *data)
{
  assert (data->page);
  vm_page_unref (data->page);
  data->page = NULL;
}

static void
ipc_data_pte_get (struct ipc_data *data)
{
  thread_pin ();
  data->ipc_pte = pmap_ipc_pte_get (&data->prev);
}

static void
ipc_data_pte_map (struct ipc_data *data, phys_addr_t pa)
{
  assert (thread_pinned () || !cpu_intr_enabled ());
  pmap_ipc_pte_set (data->ipc_pte, data->va, pa);
}

static void
ipc_data_pte_put (struct ipc_data *data)
{
  pmap_ipc_pte_put (data->ipc_pte, data->va, data->prev);
  thread_unpin ();
  data->ipc_pte = NULL;
}

static void
ipc_data_fini (void *arg)
{
  struct ipc_data *data = arg;
  if (data->ipc_pte)
    ipc_data_pte_put (data);
  if (data->page)
    vm_page_unref (data->page);
}

static int
ipc_iov_iter_refill (struct task *task, struct ipc_iov_iter *it)
{
  uint32_t cnt = MIN (it->end - it->cur, IPC_IOV_ITER_CACHE_SIZE),
           off = IPC_IOV_ITER_CACHE_SIZE - cnt,
           bsize = cnt * sizeof (struct iovec);
  ssize_t ret = ipc_bcopy (task, it->begin + it->cur, bsize,
                           &it->cache[off], bsize, IPC_COPY_FROM);
  if (ret < 0 || (ret % sizeof (struct iovec)) != 0)
    return (-EFAULT);

  it->cur += cnt;
  it->cache_idx = off;
  return (0);
}

static int
ipc_map_errno (int err)
{
  switch (err)
    {
      case EACCES:
        return (-EPERM);
      case EFAULT:
        return (-ENXIO);
      default:
        return (-err);
    }
}

/*
 * Get the physical address associated to a remote virtual address, faulting
 * in the necessary pages in case they aren't resident already. This function
 * disables interrupts but doesn't restore them when done.
 */

static int
ipc_map_addr (struct vm_map *map, const void *addr,
              struct ipc_data *data, phys_addr_t *pap)
{
  ipc_data_intr_save (data);
  int error = pmap_extract_check (map->pmap, (uintptr_t)addr,
                                  data->prot & VM_PROT_WRITE, pap);
  if (error == EACCES)
    return (-EPERM);
  else if (error)
    { // Need to fault in the destination address.
      error = vm_map_fault (map, (uintptr_t)addr, data->prot);
      if (error)
        {
          ipc_data_intr_restore (data);
          return (ipc_map_errno (error));
        }

      /*
       * Since we're running with interrupts disabled, and the address
       * has been faulted in, this call cannot fail.
       */
      error = pmap_extract (map->pmap, (uintptr_t)addr, pap);
      assert (! error);
    }

  return (0);
}

static ssize_t
ipc_bcopyv_impl (struct vm_map *r_map, const struct iovec *r_v,
                 const struct iovec *l_v, struct ipc_data *data)
{
  size_t page_off = (uintptr_t)r_v->iov_base % PAGE_SIZE,
         ret = MIN (PAGE_SIZE - page_off, MIN (r_v->iov_len, l_v->iov_len));

  phys_addr_t pa;
  int error = ipc_map_addr (r_map, r_v->iov_base, data, &pa);
  if (error)
    return (error);

  ipc_data_pte_get (data);
  ipc_data_page_ref (data, pa);
  ipc_data_pte_map (data, pa);
  ipc_data_intr_restore (data);

  if (data->direction == IPC_COPY_TO)
    memcpy ((void *)(data->va + page_off), l_v->iov_base, ret);
  else
    memcpy ((void *)l_v->iov_base, (void *)(data->va + page_off), ret);

  ipc_data_pte_put (data);
  ipc_data_page_unref (data);
  return ((ssize_t)ret);
}

static struct iovec*
ipc_iov_iter_next (struct ipc_iov_iter *it)
{ // Get the next iovec from a local iterator, or NULL if exhausted.
  while (1)
    {
      if (it->head.iov_len)
        return (&it->head);
      else if (it->cur < it->end)
        it->head = it->begin[it->cur++];
      else
        return (NULL);
    }
}

static struct iovec*
ipc_iov_iter_next_remote (struct ipc_iov_iter *it,
                          struct task *task, ssize_t *outp)
{ // Same as above, only for a remote iterator.
  while (1)
    {
      if (it->head.iov_len)
        return (&it->head);
      else if (it->cache_idx < IPC_IOV_ITER_CACHE_SIZE)
        it->head = it->cache[it->cache_idx++];
      else if (it->cur >= it->end)
        return (NULL);
      else
        {
          int error = ipc_iov_iter_refill (task, it);
          if (error)
            {
              *outp = error;
              return (NULL);
            }
        }
    }
}

ssize_t
ipc_iov_iter_copy (struct task *r_task, struct ipc_iov_iter *r_it,
                   struct ipc_iov_iter *l_it, int direction)
{
  struct ipc_data data;
  ipc_data_init (&data, direction);

  struct unw_fixup fixup;
  int error = unw_fixup_save (&fixup);
  if (unlikely (error))
    {
      ipc_data_fini (&data);
      return (-error);
    }

  for (ssize_t ret = 0 ; ; )
    {
      struct iovec *lv = ipc_iov_iter_next (l_it);
      if (! lv)
        return (ret);

      struct iovec *rv = ipc_iov_iter_next_remote (r_it, r_task, &ret);
      if (! rv)
        return (ret);

      ssize_t tmp = ipc_bcopyv_impl (r_task->map, rv, lv, &data);

      if (tmp < 0)
        return (tmp);
      else if (unlikely ((ret += tmp) < 0))
        return (-EOVERFLOW);

      iovec_adv (lv, tmp);
      iovec_adv (rv, tmp);
    }
}

ssize_t
ipc_bcopy (struct task *r_task, void *r_ptr, size_t r_size,
           void *l_ptr, size_t l_size, int direction)
{
  struct ipc_data data;
  struct unw_fixup fixup;
  int error = unw_fixup_save (&fixup);
  if (unlikely (error))
    {
      ipc_data_fini (&data);
      return (-error);
    }

  ipc_data_init (&data, direction);
  struct iovec r_v = IOVEC (r_ptr, r_size), l_v = IOVEC (l_ptr, l_size);

  for (ssize_t ret = 0 ; ; )
    {
      if (!r_v.iov_len || !l_v.iov_len)
        return (ret);

      ssize_t tmp = ipc_bcopyv_impl (r_task->map, &r_v, &l_v, &data);

      if (tmp < 0)
        return (tmp);
      else if (unlikely ((ret += tmp) < 0))
        return (-EOVERFLOW);

      iovec_adv (&r_v, tmp);
      iovec_adv (&l_v, tmp);
    }
}

static void
ipc_cspace_guard_fini (struct adaptive_lock **lockp)
{
  if (*lockp)
    adaptive_lock_release (*lockp);
}

static void
ipc_cap_iter_cleanup (struct cspace *sp, struct ipc_cap_iter *it, uint32_t idx)
{
  for (; it->cur != idx; --it->cur)
    {
      _Auto mp = it->begin + it->cur - 1;
      cspace_rem_locked (sp, mp->cap);
    }
}

static int
ipc_cap_copy_impl (struct task *r_task, struct ipc_cap_iter *r_it,
                   struct ipc_cap_iter *l_it, int direction)
{
  struct ipc_cap_iter *in_it, *out_it;
  struct cspace *in_cs, *out_cs;

  if (direction == IPC_COPY_FROM)
    {
      in_it = r_it, out_it = l_it;
      in_cs = &r_task->caps, out_cs = cspace_self ();
    }
  else
    {
      in_it = l_it, out_it = r_it;
      in_cs = cspace_self (), out_cs = &r_task->caps;
    }

  uint32_t prev = out_it->cur;
  int rv = 0;
  struct adaptive_lock *lock CLEANUP (ipc_cspace_guard_fini) = &out_cs->lock;

  ADAPTIVE_LOCK_GUARD (&in_cs->lock);
  if (likely (in_cs != out_cs))
    adaptive_lock_acquire (lock);
  else
    lock = NULL;

  for (; ipc_cap_iter_size (in_it) && ipc_cap_iter_size (out_it);
      ++in_it->cur, ++out_it->cur, ++rv)
    {
      int capx = in_it->begin[in_it->cur].cap;
      _Auto cap = cspace_get (in_cs, capx);

      if (unlikely (! cap))
        {
          ipc_cap_iter_cleanup (out_cs, out_it, prev);
          return (-EBADF);
        }

      _Auto outp = out_it->begin + out_it->cur;
      capx = cspace_add_free_locked (out_cs, cap, outp->flags);
      cap_base_rel (cap);

      if (unlikely (capx < 0))
        {
          ipc_cap_iter_cleanup (out_cs, out_it, prev);
          return (capx);
        }

      outp->cap = capx;
    }

  return (rv);
}

#define IPC_ITER_LOOP(type, fn)   \
  struct ipc_msg_##type tmp[16], *ptr = tmp;   \
  int len = ipc_##type##_iter_size (r_it), size = len * sizeof (*ptr);   \
  \
  if (unlikely (len > (int)ARRAY_SIZE (tmp)))   \
    {   \
      _Auto page = vm_page_alloc (vm_page_order (size),   \
                                  VM_PAGE_SEL_DIRECTMAP,   \
                                  VM_PAGE_KERNEL, 0);   \
      if (! page)   \
        return (-ENOMEM);   \
      \
      ptr = vm_page_direct_ptr (page);   \
    }   \
  \
  int rv = ipc_bcopy (r_task, r_it->begin + r_it->cur, size,   \
                      ptr, size, IPC_COPY_FROM);   \
  \
  if (unlikely (rv < 0))   \
    {   \
      if (ptr != tmp)   \
        vm_page_free (vm_page_lookup (vm_page_direct_pa ((uintptr_t)ptr)),   \
                      vm_page_order (size), 0);   \
      \
      return (rv);   \
    }   \
  \
  struct ipc_##type##_iter aux =   \
    {   \
      .begin = ptr,   \
      .cur = 0,   \
      .end = r_it->end - r_it->cur   \
    };   \
  \
  rv = fn (r_task, &aux, l_it, direction);   \
  if (rv >= 0)   \
    {   \
      len = rv * sizeof (*ptr);   \
      if (ipc_bcopy (r_task, r_it->begin + r_it->cur, len,   \
                     ptr, len, IPC_COPY_TO) > 0)   \
        r_it->cur = aux.cur;   \
    }   \
  \
  if (ptr != tmp)   \
    vm_page_free (vm_page_lookup (vm_page_direct_pa ((uintptr_t)ptr)),   \
                  vm_page_order (size), 0);   \
  \
  return (rv)

int
ipc_cap_iter_copy (struct task *r_task, struct ipc_cap_iter *r_it,
                   struct ipc_cap_iter *l_it, int direction)
{
  IPC_ITER_LOOP (cap, ipc_cap_copy_impl);
}

int
ipc_page_iter_copy (struct task *r_task, struct ipc_page_iter *r_it,
                    struct ipc_page_iter *l_it, int direction)
{
#define ipc_page_copy_impl(task, r_it, l_it, dir)   \
  vm_map_iter_copy ((task)->map, (r_it), (l_it), (dir))
  IPC_ITER_LOOP (page, ipc_page_copy_impl);
#undef ipc_page_copy_impl
}
