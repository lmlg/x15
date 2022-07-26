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

#include <kern/ipc.h>
#include <kern/task.h>
#include <kern/thread.h>

#include <machine/cpu.h>

#include <vm/map.h>

struct ipc_env
{
  cpu_flags_t flags;
};

static inline void
ipc_iter_bump_iovs (struct ipc_iter *it, int nr_iovs)
{
  it->cur_iov += nr_iovs;
  it->cache.idx = 0;
  it->cache.size = nr_iovs;
}

static int
ipc_iter_fill_cache_local (struct ipc_iter *it, int nr_iovs)
{
  struct vm_fixup fixup;
  int error = vm_fixup_save (&fixup);

  if (error)
    return (error);

  memcpy (it->cache.iovs, it->iovs + it->cur_iov,
          nr_iovs * sizeof (struct iovec));
  ipc_iter_bump_iovs (it, nr_iovs);
  return (0);
}

static int
ipc_iter_fill_cache (struct ipc_iter *it, struct thread *thr)
{
  int nr_iovs = MIN (IPC_IOV_CACHE_SIZE, it->nr_iovs - it->cur_iov);
  if (! nr_iovs)
    return (ENOMEM);
  else if (! thr)
    return (ipc_iter_fill_cache_local (it, nr_iovs));

  /* Need to fetch iovecs from a remote address. Do an IPC copy
   * call for simplicity's sake (this is only needed once in a
   * while to replenish the cache). */
  struct ipc_iter c_it, r_it;
  ipc_iter_init_buf (&r_it, it->iovs + it->cur_iov,
                     nr_iovs * sizeof (struct iovec));
  ipc_iter_init_buf (&c_it, it->cache.iovs, sizeof (it->cache.iovs));

  ssize_t ret = ipc_copy_iter (&r_it, thr, &c_it, thread_self ());
  if (ret < 0)
    return ((int)-ret);

  assert ((ret % sizeof (struct iovec)) == 0);
  ipc_iter_bump_iovs (it, ret / sizeof (struct iovec));
  return (0);
}

static int
ipc_iter_fetch_iov (struct ipc_iter *it, struct thread *thr)
{
  while (1)
    {
      if (it->cache.idx >= it->cache.size)
        {
          int error = ipc_iter_fill_cache (it, thr);
          if (error)
            {
              ipc_iter_set_invalid (it);
              return (error);
            }
        }

      assert (it->cache.idx < it->cache.size);
      it->cur = it->cache.iovs[it->cache.idx++];
      if (likely (it->cur.iov_len))
        return (0);
    }
}

int
ipc_iter_init_iov (struct ipc_iter *it,
                   struct iovec *iovs, uint32_t nr_iovs)
{
  it->iovs = iovs;
  it->cur_iov = 0;

  if (nr_iovs > UIO_MAXIOV)
    return (EOVERFLOW);

  it->nr_iovs = (int)nr_iovs;
  it->cache.idx = it->cache.size = 0;
  return (ipc_iter_fetch_iov (it, NULL));
}

static int
ipc_iter_adv_impl (struct ipc_iter *it, size_t off, struct thread *thr)
{
  assert (off <= it->cur.iov_len);
  it->cur.iov_base = (char *)it->cur.iov_base + off;
  it->cur.iov_len -= off;

  return (it->cur.iov_len ? 0 : ipc_iter_fetch_iov (it, thr));
}

int
ipc_iter_adv (struct ipc_iter *it, size_t off)
{
  return (ipc_iter_adv_impl (it, off, NULL));
}

static bool
ipc_inside_stack (struct thread *thread, const void *ptr)
{
  return (ptr < thread->stack &&
          (const char *)ptr >= (char *)thread->stack - PAGE_SIZE);
}

static ssize_t
ipc_copy_iter_single (struct ipc_iter *l_it, struct ipc_iter *r_it,
                      struct thread *r_thr, struct pmap *pmap, bool copy_into)
{
  struct vm_fixup fixup;
  volatile struct ipc_env env;

  int error = vm_fixup_save (&fixup);
  if (unlikely (error))
    {
      pmap_ipc_pte_clear (pmap_ipc_pte_get (), vm_map_ipc_addr ());
      cpu_intr_restore (env.flags);
      return (-error);
    }

  phys_addr_t pa;
  int prot = copy_into ? VM_PROT_RDWR : VM_PROT_READ;
  struct vm_map *r_map = r_thr->task->map;
  void *r_ptr = ipc_iter_cur_ptr (r_it);
  size_t r_size = ipc_iter_cur_size (r_it),
         l_size = ipc_iter_cur_size (l_it),
         page_off = (uintptr_t)r_ptr % PAGE_SIZE,
         ret = MIN (PAGE_SIZE - page_off, MIN (r_size, l_size));

  cpu_intr_save ((cpu_flags_t *)&env.flags);
  if (!vm_map_check_valid (r_map, (uintptr_t)r_ptr, prot) &&
      !ipc_inside_stack (r_thr, r_ptr))
    {
      cpu_intr_restore (env.flags);
      return (-EFAULT);
    }
  else if (pmap_extract (r_map->pmap, (uintptr_t)r_ptr, &pa) != 0)
    { // Need to fault in the destination address.
      error = vm_map_fault (r_map, (uintptr_t)r_ptr, prot,
                            cpu_flags_intr_enabled (env.flags) ?
                            VM_MAP_FAULT_INTR : 0);
      if (error)
        {
          cpu_intr_restore (env.flags);
          return (-error);
        }

      pmap_extract (r_map->pmap, (uintptr_t)r_ptr, &pa);
    }

  uintptr_t va = vm_map_ipc_addr ();
  _Auto pte = pmap_ipc_pte_map (pmap, va, pa);

  if (! pte)
    return (-EINTR);
  else if (copy_into)
    memcpy ((void *)(va + page_off), ipc_iter_cur_ptr (l_it), ret);
  else
    memcpy (ipc_iter_cur_ptr (l_it), (void *)(va + page_off), ret);

  pmap_ipc_pte_clear (pte, va);
  cpu_intr_restore (env.flags);

  return ((ssize_t)ret);
}

ssize_t
ipc_copy_iter (struct ipc_iter *src_it, struct thread *src_thr,
               struct ipc_iter *dst_it, struct thread *dst_thr)
{
  ssize_t ret = 0;
  struct ipc_iter *l_it = src_it, *r_it = dst_it;
  bool copy_into = src_thr == thread_self ();
  struct thread *r_thr = dst_thr;

  if (! copy_into)
    {
      l_it = dst_it, r_it = src_it;
      r_thr = src_thr;
    }

  struct pmap *pmap = thread_self()->task->map->pmap;
  while (ipc_iter_valid (l_it) && ipc_iter_valid (r_it))
    {
      ssize_t tmp = ipc_copy_iter_single (l_it, r_it, r_thr, pmap, copy_into);
      if (tmp < 0)
        return (tmp);

      /* Advance the iterators after the call because that may end up
       * calling 'ipc_copy_iter' again and the stack may overflow. */

      int error = ipc_iter_adv (l_it, tmp);
      if (error && error != ENOMEM)
        return (-error);

      error = ipc_iter_adv_impl (r_it, tmp, r_thr);
      if (error && error != ENOMEM)
        return (-error);
      else if (unlikely ((ret += tmp) < 0))
        return (-EOVERFLOW);
    }

  return (ret);
}
