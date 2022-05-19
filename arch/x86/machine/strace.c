/*
 * Copyright (c) 2012-2014 Richard Braun.
 * Copyright (c) 2018 Agustina Arzille.
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

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <kern/symbol.h>
#include <machine/pmap.h>
#include <machine/strace.h>
#include <machine/types.h>

#include <vm/kmem.h>

#ifdef __LP64__
  #define STRACE_ADDR_FORMAT   "%#018lx"
#else
  #define STRACE_ADDR_FORMAT   "%#010lx"
#endif

static void
strace_show_one (unsigned int index, uintptr_t ip)
{
  const struct symbol *symbol = symbol_lookup (ip);
  if (! symbol)
    printf ("#%02u [" STRACE_ADDR_FORMAT "]\n", index, (unsigned long) ip);
  else
    {
      uintptr_t offset = ip - symbol->addr;
      printf ("#%02u [" STRACE_ADDR_FORMAT "] %s+%#lx/%#lx\n",
              index, (unsigned long) ip, symbol->name,
              (unsigned long)offset, (unsigned long)symbol->size);
    }
}

void
strace_show (uintptr_t ip, uintptr_t bp)
{
  strace_show_one (0, ip);

  uint32_t i = 1;
  void **frame = (void **) bp;

  while (1)
    {
      if (! frame)
        break;

      phys_addr_t pa;
      int error = pmap_kextract ((uintptr_t) &frame[1], &pa);

      if (error)
        {
          printf ("strace: unmapped return address at %p\n", &frame[1]);
          break;
        }

      strace_show_one (i, (uintptr_t)frame[1]);
      error = pmap_kextract ((uintptr_t) frame, &pa);

      if (error)
        {
          printf ("strace: unmapped frame address at %p\n", frame);
          break;
        }

      ++i;
      frame = *frame;
    }
}
