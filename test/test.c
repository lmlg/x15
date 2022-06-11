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

#include <kern/fmt.h>
#include <kern/log.h>
#include <kern/macros.h>
#include <kern/symbol.h>
#include <kern/thread.h>

#include <test/test.h>

#include <vm/kmem.h>

#define PREFIX_LEN   (sizeof (QUOTE (TEST_PREFIX)) - 1)

typedef int (*test_fn_t) (void);

static void
test_thread_run (void *arg)
{
  ((test_fn_t)arg) ();
}

static bool
test_is_inline (const char *name)
{
  return (name[PREFIX_LEN] == QUOTE(TEST_INLINE_CHAR)[0]);
}

void
test_setup (void)
{
  struct symbol_iter iter;

  for (symbol_iter_init (&iter);
      symbol_iter_valid (&iter);
      symbol_iter_next (&iter))
    {
      const struct symbol *sym = iter.symbol;
      phys_addr_t pa;

      if (pmap_kextract ((uintptr_t)sym->name, &pa) != 0)
        /* This can happen for symbols that live in the BOOT section;
         * at this stage, that memory is no longer accessible, so we
         * simply skip them. */
        continue;

      size_t len = strlen (sym->name);

      if (len <= PREFIX_LEN ||
          memcmp (sym->name, QUOTE (TEST_PREFIX), PREFIX_LEN) != 0)
        continue;
      else if (test_is_inline (sym->name))
        {
          ((test_fn_t)sym->addr) ();
          continue;
        }

      char name[THREAD_NAME_SIZE];
      fmt_snprintf (name, sizeof (name), "test_%s",
                    sym->name + PREFIX_LEN + 1);

      struct thread_attr attr;
      thread_attr_init (&attr, name);
      thread_attr_set_detached (&attr);

      if (thread_create (NULL, &attr, test_thread_run, (void *)sym->addr) != 0)
        log_err ("failed to run test: %s", attr.name);
    }
}
