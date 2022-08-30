/*
 * Copyright (c) 2011-2017 Richard Braun.
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

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include <kern/cpumap.h>
#include <kern/init.h>
#include <kern/macros.h>
#include <machine/page.h>
#include <machine/pmap.h>
#include <machine/types.h>

#include <vm/defs.h>
#include <vm/kmem.h>
#include <vm/map.h>
#include <vm/object.h>
#include <vm/page.h>

static uint64_t
vm_kmem_offset (uintptr_t va)
{
  assert (va >= PMAP_START_KMEM_ADDRESS);
  return (va - PMAP_START_KMEM_ADDRESS);
}

static int __init
vm_kmem_setup (void)
{
  uint64_t size = vm_kmem_offset (PMAP_END_KMEM_ADDRESS);
  vm_object_init (vm_object_get_kernel_object (), size, NULL);
  return (0);
}

INIT_OP_DEFINE (vm_kmem_setup,
                INIT_OP_DEP (pmap_bootstrap, true),
                INIT_OP_DEP (vm_map_bootstrap, true),
                INIT_OP_DEP (vm_object_bootstrap, true),
                INIT_OP_DEP (vm_page_setup, true));

static int
vm_kmem_alloc_check (size_t size)
{
  return (!vm_page_aligned (size) || !size ? -1 : 0);
}

static int
vm_kmem_free_check (uintptr_t va, size_t size)
{
  return (!vm_page_aligned (va) ? -1 : vm_kmem_alloc_check (size));
}

void*
vm_kmem_alloc_va (size_t size)
{
  assert (vm_kmem_alloc_check (size) == 0);

  uintptr_t va = 0;
  int flags = VM_MAP_FLAGS (VM_PROT_RDWR, VM_PROT_RDWR, VM_INHERIT_NONE,
                            VM_ADV_DEFAULT, 0);
  int error = vm_map_enter (vm_map_get_kernel_map (), &va, size,
                            0, flags, NULL, 0);

  return (error ? NULL : (void *)va);
}

void
vm_kmem_free_va (void *addr, size_t size)
{
  uintptr_t va = (uintptr_t) addr;
  assert (vm_kmem_free_check (va, size) == 0);
  vm_map_remove (vm_map_get_kernel_map (), va, va + vm_page_round (size));
}

void*
vm_kmem_alloc (size_t size)
{
  size = vm_page_round (size);
  uintptr_t va = (uintptr_t) vm_kmem_alloc_va (size);

  if (! va)
    return (NULL);

  _Auto kernel_object = vm_object_get_kernel_object ();
  _Auto kernel_pmap = pmap_get_kernel_pmap ();

  for (uintptr_t start = va, end = va + size; start < end; start += PAGE_SIZE)
    {
      _Auto page = vm_page_alloc (0, VM_PAGE_SEL_HIGHMEM, VM_PAGE_KERNEL);
      if (! page)
        goto error;

      /*
       * The page becomes managed by the object and is freed in case
       * of failure.
       */
      if (vm_object_insert (kernel_object, page, vm_kmem_offset (start)) != 0)
        goto error;

      int error = pmap_enter (kernel_pmap, start, vm_page_to_pa (page),
                              VM_PROT_RDWR, PMAP_PEF_GLOBAL);

      if (error || start - va == vm_page_ptob (1000))
        goto error;
    }

  if (pmap_update (kernel_pmap) == 0)
    return ((void *)va);

error:
  vm_kmem_free ((void *) va, size);
  return (NULL);
}

void
vm_kmem_free (void *addr, size_t size)
{
  uintptr_t va = (uintptr_t)addr;
  size = vm_page_round (size);
  uintptr_t end = va + size;
  const struct cpumap *cpumap = cpumap_all ();
  _Auto kernel_pmap = pmap_get_kernel_pmap();

  for (; va < end; va += PAGE_SIZE)
    pmap_remove (kernel_pmap, va, 0, cpumap);

  pmap_update (kernel_pmap);
  vm_object_remove (vm_object_get_kernel_object (),
                    vm_kmem_offset ((uintptr_t) addr),
                    vm_kmem_offset (end));
  vm_kmem_free_va (addr, size);
}

void*
vm_kmem_map_pa (phys_addr_t pa, size_t size,
                uintptr_t *map_vap, size_t *map_sizep)
{
  _Auto kernel_pmap = pmap_get_kernel_pmap ();
  phys_addr_t start = vm_page_trunc (pa);
  size_t map_size = vm_page_round (pa + size) - start;
  uintptr_t map_va = (uintptr_t) vm_kmem_alloc_va (map_size);

  if (! map_va)
    return (NULL);

  for (uintptr_t offset = 0; offset < map_size; offset += PAGE_SIZE)
    if (pmap_enter (kernel_pmap, map_va + offset, start + offset,
                    VM_PROT_RDWR, PMAP_PEF_GLOBAL) != 0)
      goto error;

  if (pmap_update (kernel_pmap) != 0)
    goto error;

  if (map_vap != NULL)
    *map_vap = map_va;

  if (map_sizep != NULL)
    *map_sizep = map_size;

  return ((void *)(map_va + (uintptr_t)(pa & PAGE_MASK)));

error:
  vm_kmem_unmap_pa (map_va, map_size);
  return (NULL);
}

void
vm_kmem_unmap_pa (uintptr_t map_va, size_t map_size)
{
  const struct cpumap *cpumap = cpumap_all();
  _Auto kernel_pmap = pmap_get_kernel_pmap();
  uintptr_t end = map_va + map_size;

  for (uintptr_t va = map_va; va < end; va += PAGE_SIZE)
    pmap_remove (kernel_pmap, va, 0, cpumap);

  pmap_update (kernel_pmap);
  vm_kmem_free_va ((void *) map_va, map_size);
}
