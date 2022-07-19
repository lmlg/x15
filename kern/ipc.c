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
  int error;
  int pintr;   // Whether interrupts were disabled.
};

static int
ipc_iterator_next_iov (struct ipc_iterator *it)
{
  for (; it->cur_iov < it->nr_iovs; ++it->cur_iov)
    {
      struct iovec tmp;
      int error = vm_copy (&tmp, &it->iovs[it->cur_iov], sizeof (tmp));

      if (error)
        return (error);
      else if (unlikely (!tmp.iov_len))
        // Skip empty iovec's.
        continue;

      it->cur_ptr = tmp.iov_base;
      it->cur_size = tmp.iov_len;
      return (0);
    }

  ipc_iterator_set_invalid (it);
  return (ENOMEM);
}

int
ipc_iterator_init_iov (struct ipc_iterator *it,
                       struct iovec *iovs, uint32_t nr_iovs)
{
  it->iovs = iovs;
  it->cur_iov = 0;

  if (nr_iovs > UIO_MAXIOV)
    return (EOVERFLOW);

  it->nr_iovs = (int)nr_iovs;
  return (ipc_iterator_next_iov (it));
}

int
ipc_iterator_adv (struct ipc_iterator *it, size_t off)
{
  assert (off <= it->cur_size);
  it->cur_ptr = (char *)it->cur_ptr + off;
  it->cur_size -= off;

  if (it->cur_size)
    // Still more data in the current entry.
    return (0);

  ++it->cur_iov;
  return (ipc_iterator_next_iov (it));
}

static bool
ipc_inside_stack (struct thread *thread, const void *ptr)
{
  return (ptr < thread->stack &&
          (const char *)ptr >= (char *)thread->stack - PAGE_SIZE);
}

static ssize_t
ipc_copy_iter_single (struct ipc_iterator *src_it, struct thread *src_thr,
                      struct ipc_iterator *dst_it, struct thread *dst_thr)
{
  struct vm_map *src_map = src_thr->task->map, *dst_map = dst_thr->task->map;
  struct vm_fixup fixup;
  volatile struct ipc_env env = { .pintr = 0 };

  env.error = vm_fixup_save (&fixup);
  if (env.error)
    {
      if (env.pintr)
        cpu_intr_restore (env.flags);

      pmap_update (src_map->pmap);
      return (-env.error);
    }

  phys_addr_t pa;
  void *dst_ptr = ipc_iterator_cur_ptr (dst_it);
  size_t dst_size = ipc_iterator_cur_size (dst_it),
         src_size = ipc_iterator_cur_size (src_it),
         page_off = (uintptr_t)dst_ptr % PAGE_SIZE,
         ret = MIN (PAGE_SIZE - page_off, MIN (dst_size, src_size));

  cpu_intr_save ((cpu_flags_t *)&env.flags);
  if (!vm_map_check_valid (dst_map, (uintptr_t)dst_ptr, VM_PROT_WRITE) &&
      !ipc_inside_stack (dst_thr, dst_ptr))
    return (-EFAULT);
  else if (pmap_extract (dst_map->pmap, (uintptr_t)dst_ptr, &pa) != 0)
    { // Need to fault in the destination address.
      int rv = vm_map_fault (dst_map, (uintptr_t)dst_ptr, VM_PROT_RDWR,
                             cpu_flags_intr_enabled (env.flags) ?
                             VM_MAP_FAULT_INTR : 0);
      if (rv)
        {
          cpu_intr_restore (env.flags);
          return (rv);
        }

      pmap_extract (dst_map->pmap, (uintptr_t)dst_ptr, &pa);
    }

  uintptr_t va = vm_map_ipc_addr ();
  pmap_enter (src_map->pmap, va, pa, VM_PROT_RDWR, PMAP_NO_CHECK);
  pmap_update (src_map->pmap);

  /* Schedule the removal now so that even if we get an address violation,
   * we can maintain pmap consistency. */
  pmap_remove (src_map->pmap, va, PMAP_NO_CHECK, NULL);

  // Also signal that interrupts have been disabled.
  env.pintr = 1;

  memcpy ((void *)(va + page_off), ipc_iterator_cur_ptr (src_it), ret);
  cpu_intr_restore (env.flags);

  ipc_iterator_adv (src_it, ret);
  ipc_iterator_adv (dst_it, ret);

  return ((ssize_t)ret);
}

ssize_t
ipc_copy_iter (struct ipc_iterator *src_it, struct thread *src_thr,
               struct ipc_iterator *dst_it, struct thread *dst_thr)
{
  ssize_t ret = 0;

  while (ipc_iterator_valid (src_it) && ipc_iterator_valid (dst_it))
    {
      ssize_t tmp = ipc_copy_iter_single (src_it, src_thr, dst_it, dst_thr);

      if (tmp < 0)
        return (tmp);
      else if (unlikely ((ret += tmp) < 0))
        return (-EOVERFLOW);
    }

  return (ret);
}
