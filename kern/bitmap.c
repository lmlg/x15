/*
 * Copyright (c) 2013-2015 Richard Braun.
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
 * Upstream site with license notes :
 * http://git.sceen.net/rbraun/librbraun.git/
 */

#include <limits.h>
#include <string.h>

#include <kern/bitmap.h>
#include <kern/bitmap_i.h>

int
bitmap_cmp (const unsigned long *a, const unsigned long *b, int nr_bits)
{
  int n = BITMAP_LONGS (nr_bits) - 1;
  if (n)
    {
      int rv = memcmp (a, b, n * sizeof (unsigned long));

      if (rv)
        return (rv);

      nr_bits -= n * LONG_BIT;
    }

  unsigned long last_a = a[n], last_b = b[n];
  if (nr_bits != LONG_BIT)
    {
      unsigned long mask = (1UL << nr_bits) - 1;
      last_a &= mask;
      last_b &= mask;
    }

  return (last_a == last_b ? 0 : (last_a < last_b ? -1 : 1));
}

static inline unsigned long
bitmap_find_next_compute_complement (unsigned long word, int nr_bits)
{
  if (nr_bits < LONG_BIT)
    word |= (((unsigned long)-1) << nr_bits);

  return (~word);
}

int
bitmap_find_next_bit (const unsigned long *bm, int nr_bits, int bit,
                      int complement)
{
  const unsigned long *start = bm,
                      *end = bm + BITMAP_LONGS (nr_bits);

  if (bit >= LONG_BIT)
    {
      bitmap_lookup (&bm, &bit);
      nr_bits -= ( (bm - start) * LONG_BIT);
    }

  unsigned long word = *bm;
  if (complement)
    word = bitmap_find_next_compute_complement (word, nr_bits);

  if (bit < LONG_BIT)
    word &= ~ (bitmap_mask (bit) - 1);

  for (;;)
    {
      bit = __builtin_ffsl (word);

      if (bit != 0)
        return (((bm - start) * LONG_BIT) + bit - 1);
      else if (++bm >= end)
        return (-1);

      nr_bits -= LONG_BIT;
      word = *bm;

      if (complement)
        word = bitmap_find_next_compute_complement (word, nr_bits);
    }
}
