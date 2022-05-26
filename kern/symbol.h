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

#ifndef KERN_SYMBOL_H
#define KERN_SYMBOL_H

#include <stdbool.h>
#include <stdint.h>

#include <kern/macros.h>

#define __symbol_table __section (".symbol")

/*
 * Symbol structure.
 *
 * This structure is public.
 */
struct symbol
{
  uintptr_t addr;
  uintptr_t size;
  const char *name;
};

// Symbol table iterator.
struct symbol_iter
{
  size_t idx;
  const struct symbol *symbol;
};

/*
 * Look up a symbol from an address.
 *
 * NULL is returned if no symbol was found for the given address.
 */
const struct symbol* symbol_lookup (uintptr_t addr);

// Initialize a symbol table iterator.
void symbol_iter_init (struct symbol_iter *iter);

// Move the symbol table iterator. Returns true if there are still entries.
bool symbol_iter_next (struct symbol_iter *iter);

// Test if an iterator is valid.
static inline bool
symbol_iter_valid (const struct symbol_iter *iter)
{
  return (iter->symbol != NULL);
}

#endif
