/*
 * Copyright (c) 2013-2014 Richard Braun.
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

#include <errno.h>
#include <stddef.h>

#include <kern/bitmap.h>
#include <kern/cpumap.h>
#include <kern/init.h>
#include <kern/kmem.h>
#include <kern/macros.h>
#include <machine/cpu.h>

static struct cpumap cpumap_active_cpus __read_mostly = { { 1 } };

static struct kmem_cache cpumap_cache;

static int __init
cpumap_setup (void)
{
  kmem_cache_init (&cpumap_cache, "cpumap", sizeof (struct cpumap), 0, NULL, 0);
  cpumap_zero (&cpumap_active_cpus);

  for (unsigned i = 0; i < cpu_count (); i++)
    cpumap_set (&cpumap_active_cpus, i);

  return (0);
}

INIT_OP_DEFINE (cpumap_setup,
                INIT_OP_DEP (kmem_setup, true),
                INIT_OP_DEP (cpu_mp_probe, true));

const struct cpumap*
cpumap_all (void)
{
  return (&cpumap_active_cpus);
}

int
cpumap_create (struct cpumap **cpumapp)
{
  struct cpumap *cpumap = kmem_cache_alloc (&cpumap_cache);
  if (! cpumap)
    return (ENOMEM);

  *cpumapp = cpumap;
  return (0);
}

void
cpumap_destroy (struct cpumap *cpumap)
{
  kmem_cache_free (&cpumap_cache, cpumap);
}

int
cpumap_check (const struct cpumap *cpumap)
{
  int index = bitmap_find_first (cpumap->cpus, cpu_count ());
  return (index < 0 ? EINVAL : 0);
}
