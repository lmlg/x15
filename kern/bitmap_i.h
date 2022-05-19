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

#ifndef KERN_BITMAP_I_H
#define KERN_BITMAP_I_H

#include <limits.h>

#include <kern/macros.h>

#define BITMAP_LONGS(nr_bits)   DIV_CEIL (nr_bits, LONG_BIT)

/*
 * Adjust the bitmap pointer and the bit index so that the latter refers
 * to a bit inside the word pointed by the former.
 *
 * Implemented as a macro for const-correctness.
 */
#define bitmap_lookup(bmp, bitp)   \
MACRO_BEGIN   \
  int i_ = BITMAP_LONGS (*(bitp) + 1) - 1;   \
  *(bmp) += i_;   \
  *(bitp) -= i_ * LONG_BIT;   \
MACRO_END

static inline unsigned long
bitmap_mask (int bit)
{
  return (1UL << bit);
}

/*
 * Return the index of the next set bit in the bitmap, starting (and
 * including) the given bit index, or -1 if the bitmap is empty. If
 * complement is true, bits are toggled before searching so that the
 * result is the index of the next zero bit.
 */
int bitmap_find_next_bit (const unsigned long *bm, int nr_bits, int bit,
                          int complement);

#endif
