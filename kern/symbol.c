/*
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

#include <kern/macros.h>
#include <kern/symbol.h>

/*
 * XXX Clang doesn't consider that weak symbols may change at link time
 * by default, which turns the lookup into a no-op when optimizations
 * are enabled. Make these variables volatile to work around this issue.
 */
const volatile size_t symbol_table_size __weak;
const struct symbol* volatile symbol_table_ptr __weak;

const struct symbol*
symbol_lookup (uintptr_t addr)
{
  const struct symbol *table = symbol_table_ptr;
  size_t size = symbol_table_size;

  for (size_t i = 0; i < size; i++)
    {
      const struct symbol *symbol = &table[i];

      if (!symbol->name || !symbol->size)
        continue;
      else if (addr >= symbol->addr && addr < symbol->addr + symbol->size)
        return (symbol);
    }

  return (NULL);
}

static inline bool
symbol_iter_adv (struct symbol_iter *iter)
{
  const struct symbol *table = symbol_table_ptr;
  size_t size = symbol_table_size;

  while (1)
    {
      const struct symbol *symbol = &table[iter->idx];
      if (symbol->name && symbol->size)
        {
          iter->symbol = symbol;
          return (true);
        }
      else if (++iter->idx >= size)
        {
          iter->symbol = NULL;
          return (false);
        }
    }
}

void
symbol_iter_init (struct symbol_iter *iter)
{
  iter->idx = 0;
  symbol_iter_adv (iter);
}

bool
symbol_iter_next (struct symbol_iter *iter)
{
  if (!symbol_iter_valid (iter))
    return (false);

  ++iter->idx;
  return (symbol_iter_adv (iter));
}
