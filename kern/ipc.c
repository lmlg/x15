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
#include <kern/unwind.h>

#include <machine/cpu.h>

#include <vm/map.h>
#include <vm/page.h>

struct ipc_data
{
  cpu_flags_t cpu_flags;
  uintptr_t va;
  int direction;
  int prot;
  int fault_intr;
  bool nintr;
  struct pmap_ipc_pte *ipc_pte;
  struct vm_page *page;
};

static void
ipc_data_init (struct ipc_data *data, int direction)
{
  data->direction = direction;
  data->prot = direction == IPC_COPY_FROM ? VM_PROT_READ : VM_PROT_RDWR;
  data->va = vm_map_ipc_addr ();
  data->fault_intr = cpu_intr_enabled () ? VM_MAP_FAULT_INTR : 0;
  data->ipc_pte = NULL;
  data->nintr = false;
  data->page = NULL;
}

static void
ipc_data_set (struct ipc_data *data)
{
  cpu_intr_save (&data->cpu_flags);
  data->nintr = true;
}

static void
ipc_data_reset (struct ipc_data *data)
{
  cpu_intr_restore (data->cpu_flags);
  data->nintr = false;
}

static void
ipc_data_fini (void *arg)
{
  struct ipc_data *data = arg;
  if (data->ipc_pte)
    pmap_ipc_pte_put (data->ipc_pte, data->va);
  if (data->page)
    vm_page_unref (data->page);
  if (data->nintr)
    cpu_intr_restore (data->cpu_flags);
}

static void
ipc_data_pte_map (struct ipc_data *data, phys_addr_t pa)
{
  data->ipc_pte = pmap_ipc_pte_get ();
  pmap_ipc_pte_set (data->ipc_pte, data->va, pa);
}

static int
ipc_iov_iter_refill (struct task *task, struct ipc_iov_iter *it)
{
  uint32_t cnt = MIN (it->end - it->cur, IPC_IOV_ITER_CACHE_SIZE),
           off = IPC_IOV_ITER_CACHE_SIZE - cnt,
           bsize = cnt * sizeof (struct iovec);
  ssize_t ret = ipc_bcopy (task, it->begin + it->cur, bsize,
                           &it->cache[off], bsize, IPC_COPY_FROM);
  if (ret < 0)
    return (-EFAULT);

  assert ((ret % sizeof (struct iovec)) == 0);
  it->cur += cnt;
  it->cache_idx = off;
  return (0);
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
  ipc_data_set (data);
  if (pmap_extract (map->pmap, (uintptr_t)addr, pap))
    { // Need to fault in the destination address.
      int error = vm_map_fault (map, (uintptr_t)addr, data->prot,
                                data->fault_intr);
      if (error)
        return (-error);

      /* Since we're running with interrupts disabled, and the address
       * has been faulted in, this call cannot fail. */
      pmap_extract (map->pmap, (uintptr_t)addr, pap);
    }

  return (0);
}

static ssize_t
ipc_bcopyv_impl (struct vm_map *r_map, struct iovec *r_v,
                 struct iovec *l_v, struct ipc_data *data)
{
  phys_addr_t pa;
  int error = ipc_map_addr (r_map, r_v->iov_base, data, &pa);
  if (error)
    return (error);

  size_t page_off = (uintptr_t)r_v->iov_base % PAGE_SIZE,
         ret = MIN (PAGE_SIZE - page_off, MIN (r_v->iov_len, l_v->iov_len));

  ipc_data_pte_map (data, pa);

  if (data->direction == IPC_COPY_TO)
    memcpy ((void *)(data->va + page_off), l_v->iov_base, ret);
  else
    memcpy (l_v->iov_base, (void *)(data->va + page_off), ret);

  pmap_ipc_pte_put (data->ipc_pte, data->va);
  ipc_data_reset (data);
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

static void
ipc_iov_adv (struct iovec *iov, ssize_t off)
{
  iov->iov_base = (char *)iov->iov_base + off;
  iov->iov_len -= off;
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
      struct iovec *lv = ipc_iov_iter_next (l_it),
                   *rv = ipc_iov_iter_next_remote (r_it, r_task, &ret);

      if (!lv || !rv)
        return (ret);

      ssize_t tmp = ipc_bcopyv_impl (r_task->map, rv, lv, &data);

      if (tmp < 0)
        return (tmp);
      else if (unlikely ((ret += tmp) < 0))
        return (-EOVERFLOW);

      ipc_iov_adv (lv, tmp);
      ipc_iov_adv (rv, tmp);
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
  struct iovec r_v = { .iov_base = r_ptr, .iov_len = r_size },
               l_v = { .iov_base = l_ptr, .iov_len = l_size };

  for (ssize_t ret = 0 ; ; )
    {
      if (!r_v.iov_len || !l_v.iov_len)
        return (ret);

      ssize_t tmp = ipc_bcopyv_impl (r_task->map, &r_v, &l_v, &data);

      if (tmp < 0)
        return (tmp);
      else if (unlikely ((ret += tmp) < 0))
        return (-EOVERFLOW);

      ipc_iov_adv (&r_v, tmp);
      ipc_iov_adv (&l_v, tmp);
    }
}

ssize_t
ipc_bcopyv (struct task *r_task, struct iovec *r_iov, uint32_t r_niov,
            struct iovec *l_iov, uint32_t l_niov, int direction)
{
  struct ipc_iov_iter r_it, l_it;

  ipc_iov_iter_init (&l_it, l_iov, l_niov);
  ipc_iov_iter_init (&r_it, r_iov, r_niov);
  return (ipc_iov_iter_copy (r_task, &r_it, &l_it, direction));
}

int
ipc_page_iter_copy (struct task *r_task, struct ipc_page_iter *r_it,
                    struct ipc_page_iter *l_it, int direction)
{
  struct vm_map *map_in, *map_out;
  struct ipc_page_iter *it_in, *it_out;
  _Auto l_map = thread_self()->task->map;

  if (direction == IPC_COPY_FROM)
    {
      map_in = r_task->map, map_out = l_map;
      it_in = r_it, it_out = l_it;
    }
  else
    {
      map_in = l_map, map_out = r_task->map;
      it_in = l_it, it_out = r_it;
    }

  struct ipc_data data CLEANUP (ipc_data_fini);
  struct unw_fixup fixup;
  int error = unw_fixup_save (&fixup);

  if (unlikely (error))
    return (-error);

  ipc_data_init (&data, direction);
  phys_addr_t pa;
  error = ipc_map_addr (r_task->map, r_it->begin + r_it->cur, &data, &pa);

  if (error)
    return (error);

  ipc_data_pte_map (&data, pa);
  vm_page_ref (data.page = vm_page_lookup (pa));
  ipc_data_reset (&data);

  _Auto elems_pp = ((uintptr_t)r_it->cur % PAGE_SIZE) / sizeof (*r_it->begin);
  int i;

  for (i = 0; i < MIN (ipc_page_iter_size (it_in),
                       ipc_page_iter_size (it_out)); ++i)
    {
      if (! elems_pp)
        {
          error = ipc_map_addr (r_task->map, r_it->begin + r_it->cur,
                                &data, &pa);
          if (error)
            return (error);

          pmap_ipc_pte_set (data.ipc_pte, data.va, pa);
          vm_page_unref (data.page);
          vm_page_ref (data.page = vm_page_lookup (pa));
          ipc_data_reset (&data);

          elems_pp = PAGE_SIZE / sizeof (*r_it->begin);
        }

      _Auto page = it_in->begin[it_in->cur++];
      uintptr_t end = page.addr + page.size;

      do
        {
          struct vm_map_entry entry CLEANUP (vm_map_entry_put);
          _Auto outp = &it_out->begin[it_out->cur];

          error = vm_map_lookup (map_in, page.addr, &entry);

          if (error)
            return (error);
          else if ((VM_MAP_MAXPROT (entry.flags) & page.prot) != page.prot)
            return (-EACCES);
          else if (entry.flags & VM_MAP_ANON)
            { // Adjust the offset for anonymous pages.
              entry.offset += page.addr - entry.start;
              entry.flags &= ~VM_MAP_ANON;
            }

          size_t size = MIN (end - page.addr, page.size);
          error = vm_map_enter (map_out, &outp->addr, size,
                                0, entry.flags, entry.object, entry.offset);
          if (error)
            return (error);

          outp->prot = page.prot;
          outp->size = size;
          page.addr += size;
          ++it_out->cur;
        }
      while (page.addr < end && ipc_page_iter_size (it_out));

      --elems_pp;
    }

  return (i);
}

int
ipc_copy_pages (struct task *r_task, struct ipc_msg_page *r_pages,
                uint32_t r_npages, struct ipc_msg_page *l_pages,
                uint32_t l_npages, int direction)
{
  struct ipc_page_iter r_it, l_it;
  ipc_page_iter_init (&r_it, r_pages, r_npages);
  ipc_page_iter_init (&l_it, l_pages, l_npages);
  return (ipc_page_iter_copy (r_task, &r_it, &l_it, direction));
}
