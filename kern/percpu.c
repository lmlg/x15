/*
 * Copyright (c) 2014-2017 Richard Braun.
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
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <kern/init.h>
#include <kern/log.h>
#include <kern/macros.h>
#include <kern/panic.h>
#include <kern/percpu.h>
#include <kern/slist.h>

#include <machine/cpu.h>

#include <vm/kmem.h>
#include <vm/page.h>

void *percpu_areas[CONFIG_MAX_CPUS] __read_mostly;

static void *percpu_area_content __initdata;
static size_t percpu_area_size __initdata;
static int percpu_skip_warning __initdata;

static struct slist percpu_ops __initdata;

static void __init
percpu_op_run (const struct percpu_op *op)
{
  op->fn ();
}

static int __init
percpu_bootstrap (void)
{
  percpu_areas[0] = &_percpu;
  return (0);
}

INIT_OP_DEFINE (percpu_bootstrap);

static int __init
percpu_setup (void)
{
  slist_init (&percpu_ops);
  percpu_area_size = &_percpu_end - &_percpu;
  log_info ("percpu: max_cpus: %u, section size: %zuk",
            CONFIG_MAX_CPUS, percpu_area_size >> 10);
  assert (vm_page_aligned (percpu_area_size));

  if (! percpu_area_size)
    return (0);

  uint32_t order = vm_page_order (percpu_area_size);
  _Auto page = vm_page_alloc (order, VM_PAGE_SEL_DIRECTMAP, VM_PAGE_KERNEL, 0);

  if (! page)
    panic ("percpu: unable to allocate memory for percpu area content");

  percpu_area_content = vm_page_direct_ptr (page);
  memcpy (percpu_area_content, &_percpu, percpu_area_size);
  return (0);
}

INIT_OP_DEFINE (percpu_setup,
                INIT_OP_DEP (percpu_bootstrap, true),
                INIT_OP_DEP (vm_page_setup, true));

void __init
percpu_register_op (struct percpu_op *op)
{
  slist_insert_tail (&percpu_ops, &op->node);
  // Run on BSP.
  percpu_op_run (op);
}

int __init
percpu_add (uint32_t cpu)
{
  if (cpu >= ARRAY_SIZE (percpu_areas))
    {
      if (!percpu_skip_warning)
        {
          log_warning ("percpu: ignoring processor beyond id %zu",
                       ARRAY_SIZE (percpu_areas) - 1);
          percpu_skip_warning = 1;
        }

      return (EINVAL);
    }
  else if (percpu_areas[cpu])
    {
      log_err ("percpu: id %u ignored, already registered", cpu);
      return (EINVAL);
    }

  if (! percpu_area_size)
    goto out;

  unsigned int order = vm_page_order (percpu_area_size);
  _Auto page = vm_page_alloc (order, VM_PAGE_SEL_DIRECTMAP, VM_PAGE_KERNEL, 0);

  if (! page)
    {
      log_err ("percpu: unable to allocate percpu area");
      return (ENOMEM);
    }

  percpu_areas[cpu] = vm_page_direct_ptr (page);
  memcpy (percpu_area (cpu), percpu_area_content, percpu_area_size);

out:
  return (0);
}

void __init
percpu_ap_setup (void)
{
  struct percpu_op *op;
  slist_for_each_entry (&percpu_ops, op, node)
    percpu_op_run (op);
}

static int __init
percpu_cleanup (void)
{
  uintptr_t va = (uintptr_t) percpu_area_content;
  _Auto page = vm_page_lookup (vm_page_direct_pa (va));
  vm_page_free (page, vm_page_order (percpu_area_size), 0);
  return (0);
}

INIT_OP_DEFINE (percpu_cleanup,
                INIT_OP_DEP (cpu_mp_probe, true),
                INIT_OP_DEP (percpu_setup, true),
                INIT_OP_DEP (vm_page_setup, true));
