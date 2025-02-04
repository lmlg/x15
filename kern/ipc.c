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
  uint32_t flags;
  int prot;
  struct pmap_window *window;
  struct vm_page *page;
};

static void
ipc_data_init (struct ipc_data *data, uint32_t flags)
{
  data->flags = flags;
  data->prot = (flags & IPC_COPY_FROM) ? VM_PROT_READ : VM_PROT_RDWR;
  data->window = NULL;
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
ipc_data_win_get (struct ipc_data *data)
{
  thread_pin ();
  data->window = pmap_window_get (0);
}

static void
ipc_data_win_map (struct ipc_data *data, phys_addr_t pa)
{
  pmap_window_set (data->window, pa);
}

static void
ipc_data_win_put (struct ipc_data *data)
{
  pmap_window_put (data->window);
  thread_unpin ();
  data->window = NULL;
}

static void
ipc_data_fini (void *arg)
{
  struct ipc_data *data = arg;
  if (data->window)
    ipc_data_win_put (data);
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
                           &it->cache[off], bsize,
                           IPC_COPY_FROM | IPC_CHECK_REMOTE);
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
  if (error)
    { // Need to page in the destination address.
      error = vm_map_fault (map, (uintptr_t)addr, data->prot);
      if (error)
        {
          ipc_data_intr_restore (data);
          return (ipc_map_errno (error));
        }

      /*
       * Since we're running with interrupts disabled, and the address
       * has been paged in, this call cannot fail.
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

  ipc_data_win_get (data);
  ipc_data_page_ref (data, pa);
  ipc_data_win_map (data, pa);
  ipc_data_intr_restore (data);

  void *va = (char *)pmap_window_va (data->window) + page_off;

  if (data->flags & IPC_COPY_TO)
    memcpy (va, l_v->iov_base, ret);
  else
    memcpy ((void *)l_v->iov_base, va, ret);

  ipc_data_win_put (data);
  ipc_data_page_unref (data);

  return ((ssize_t)ret);
}

struct iovec*
ipc_iov_iter_usrnext (struct ipc_iov_iter *it, ssize_t *errp)
{
  while (1)
    {
      if (it->head.iov_len)
        return (&it->head);
      else if (it->cur >= it->end)
        return (NULL);

      _Auto iov = it->begin + it->cur;
      if (errp && !user_check_range (iov->iov_base, iov->iov_len))
        {
          *errp = -EFAULT;
          return (NULL);
        }

      it->head = *iov;
      ++it->cur;
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
                   struct ipc_iov_iter *l_it, uint32_t flags)
{
  struct ipc_data data;
  ipc_data_init (&data, flags);

  struct unw_fixup fixup;
  int error = unw_fixup_save (&fixup);
  if (unlikely (error))
    {
      ipc_data_fini (&data);
      return (-error);
    }

  ssize_t ret = 0, *r_err = (flags & IPC_CHECK_REMOTE) ? &ret : NULL,
          *l_err = (flags & IPC_CHECK_LOCAL) ? &ret : NULL;

  while (1)
    {
      struct iovec *lv = ipc_iov_iter_usrnext (l_it, l_err);
      if (! lv)
        return (ret);

      struct iovec *rv = ipc_iov_iter_next_remote (r_it, r_task, r_err);
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
           void *l_ptr, size_t l_size, uint32_t flags)
{
  if (((flags & IPC_CHECK_REMOTE) &&
        !user_check_range (r_ptr, r_size)) ||
      ((flags & IPC_CHECK_LOCAL) &&
       !user_check_range (l_ptr, l_size)))
    return (-EFAULT);

  struct ipc_data data;
  struct unw_fixup fixup;
  int error = unw_fixup_save (&fixup);
  if (unlikely (error))
    {
      ipc_data_fini (&data);
      return (-error);
    }

  ipc_data_init (&data, flags);
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

static int
ipc_cap_iter_cleanup (struct cspace *sp, struct ipc_cap_iter *it,
                      uint32_t idx, int error)
{
  for (; it->cur != idx; --it->cur)
    {
      _Auto mp = it->begin + it->cur - 1;
      cspace_rem_locked (sp, mp->cap);
    }

  return (error);
}

static int
ipc_cap_copy_one (struct cspace *in_cs, struct cspace *out_cs,
                  struct ipc_cap_iter *in_it, struct ipc_cap_iter *out_it)
{
  int mark, capx = in_it->begin[in_it->cur].cap;
  _Auto cap = cspace_get_all (in_cs, capx, &mark);

  if (unlikely (! cap))
    return (-EBADF);

  _Auto outp = out_it->begin + out_it->cur;
  capx = cspace_add_free_locked (out_cs, cap, outp->flags & ~CSPACE_MASK);
  cap_base_rel (cap);

  if (unlikely (capx < 0))
    return (capx);
  else if (mark && cap_type (cap) == CAP_TYPE_CHANNEL &&
           cap_channel_mark_shared (cap))
    cap_base_rel (cap);

  outp->cap = capx;
  ++in_it->cur;
  ++out_it->cur;
  return (0);
}

static int
ipc_cap_copy_impl (struct task *r_task, struct ipc_cap_iter *r_it,
                   struct ipc_cap_iter *l_it, uint32_t flags)
{
  struct ipc_cap_iter *in_it, *out_it;
  struct cspace *in_cs, *out_cs;

  if (flags & IPC_COPY_FROM)
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

  for (; ipc_cap_iter_size (in_it) && ipc_cap_iter_size (out_it); ++rv)
    {
      int tmp = ipc_cap_copy_one (in_cs, out_cs, in_it, out_it);
      if (unlikely (tmp != 0))
        return (ipc_cap_iter_cleanup (out_cs, out_it, prev, tmp));
    }

  return (rv);
}

static void*
ipc_buffer_alloc (void *array, int iter_len, int room, int size)
{
  if (iter_len <= room)
    return (array);

  _Auto page = vm_page_alloc (vm_page_order (size), VM_PAGE_SEL_DIRECTMAP,
                              VM_PAGE_KERNEL, VM_PAGE_SLEEP);
  return (page ? vm_page_direct_ptr (page) : NULL);
}

static void
ipc_buffer_free (void *array, void *ptr, int size)
{
  if (array != ptr)
    vm_page_free (vm_page_lookup (vm_page_direct_pa ((uintptr_t)ptr)),
                  vm_page_order (size), VM_PAGE_SLEEP);
}

#define IPC_ITER_LOOP(type, fn)   \
  struct ipc_msg_##type tmp[16], *ptr;   \
  int len = ipc_##type##_iter_size (r_it), size = len * sizeof (*ptr);   \
  \
  ptr = ipc_buffer_alloc (tmp, len, (int)ARRAY_SIZE (tmp), size);   \
  if (! ptr)   \
    return (-ENOMEM);   \
  \
  int rv = ipc_bcopy (r_task, r_it->begin + r_it->cur, size, ptr, size,   \
                      IPC_COPY_FROM | (flags & IPC_CHECK_REMOTE));   \
  \
  if (unlikely (rv < 0))   \
    {   \
      ipc_buffer_free (tmp, ptr, size);   \
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
  struct unw_fixup fx;   \
  rv = unw_fixup_save (&fx);   \
  rv = rv == 0 ? fn (r_task, &aux, l_it, flags) : -rv;   \
  if (rv >= 0)   \
    {   \
      len = rv * sizeof (*ptr);   \
      if (ipc_bcopy (r_task, r_it->begin + r_it->cur, len,   \
                     ptr, len, IPC_COPY_TO | IPC_CHECK_REMOTE) > 0)   \
        r_it->cur += aux.cur;   \
    }   \
  \
  ipc_buffer_free (tmp, ptr, size);   \
  return (rv)

int
ipc_cap_iter_copy (struct task *r_task, struct ipc_cap_iter *r_it,
                   struct ipc_cap_iter *l_it, uint32_t flags)
{
  if ((flags & IPC_CHECK_LOCAL) &&
      !user_check_range (l_it->begin, l_it->end * sizeof (*l_it->begin)))
    return (-EFAULT);

  IPC_ITER_LOOP (cap, ipc_cap_copy_impl);
}

int
ipc_vme_iter_copy (struct task *r_task, struct ipc_vme_iter *r_it,
                   struct ipc_vme_iter *l_it, uint32_t flags)
{
  if ((flags & IPC_CHECK_LOCAL) &&
      !user_check_range (l_it->begin, l_it->end * sizeof (*l_it->begin)))
    return (-EFAULT);

#define ipc_vme_copy_impl(task, r_it, l_it, flg)   \
  vm_map_iter_copy ((task)->map, (r_it), (l_it), (flg))
  IPC_ITER_LOOP (vme, ipc_vme_copy_impl);
#undef ipc_vme_copy_impl
}
