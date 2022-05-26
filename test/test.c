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

#include <assert.h>
#include <string.h>

#include <kern/macros.h>
#include <kern/symbol.h>

#include <test/test.h>

#include <vm/kmem.h>

void
test_setup (void)
{
  struct symbol_iter iter;
  const size_t prefix_len = sizeof (QUOTE (TEST_PREFIX)) - 1;

  for (symbol_iter_init (&iter);
      symbol_iter_valid (&iter);
      symbol_iter_next (&iter))
    {
      const struct symbol *sym = iter.symbol;
      phys_addr_t pa;

      if (pmap_kextract ((uintptr_t)sym->name, &pa) != 0)
        continue;

      size_t len = strlen (sym->name);

      if (len <= prefix_len ||
          memcmp (sym->name, QUOTE (TEST_PREFIX), prefix_len) != 0)
        continue;

      ((int (*) (void))sym->addr) ();
    }
}
