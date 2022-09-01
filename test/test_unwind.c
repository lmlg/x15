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
 *
 * This module tests the generic unwind API.
 */

#include <kern/unwind.h>

#include <test/test.h>

static void __noinline
test_unw_manip (volatile int *ptr)
{
  *ptr += 42;
}

TEST_DEFERRED (unwind)
{
  volatile int value = 0;
  struct unw_fixup fx;
  int rv = unw_fixup_save (&fx);

  if (! rv)
    {
      test_unw_manip (&value);
      unw_fixup_jmp (&fx, -3);
      test_unw_manip (&value);
    }

  assert (value != 0);
  assert (rv == -3);
  return (TEST_OK);
}
