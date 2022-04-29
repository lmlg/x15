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
 *
 *
 * Arbitrary-length bit arrays.
 *
 * Most functions do not check whether the given parameters are valid. This
 * is the responsibility of the caller.
 */

#ifndef KERN_BITMAP_H
#define KERN_BITMAP_H

#include <limits.h>
#include <string.h>

#include <kern/atomic.h>
#include <kern/bitmap_i.h>

#define BITMAP_DECLARE(name, nr_bits) unsigned long name[BITMAP_LONGS(nr_bits)]

int bitmap_cmp(const unsigned long *a, const unsigned long *b, int nr_bits);

static inline void
bitmap_zero(unsigned long *bm, int nr_bits)
{
    int n;

    n = BITMAP_LONGS(nr_bits);
    memset(bm, 0, n * sizeof(unsigned long));
}

static inline void
bitmap_fill(unsigned long *bm, int nr_bits)
{
    int n;

    n = BITMAP_LONGS(nr_bits);
    memset(bm, 0xff, n * sizeof(unsigned long));
}

static inline void
bitmap_copy(unsigned long *dest, const unsigned long *src, int nr_bits)
{
    int n;

    n = BITMAP_LONGS(nr_bits);
    memcpy(dest, src, n * sizeof(unsigned long));
}

static inline void
bitmap_set(unsigned long *bm, int bit)
{
    if (bit >= LONG_BIT) {
        bitmap_lookup(&bm, &bit);
    }

    *bm |= bitmap_mask(bit);
}

static inline void
bitmap_set_atomic(unsigned long *bm, int bit)
{
    if (bit >= LONG_BIT) {
        bitmap_lookup(&bm, &bit);
    }

    atomic_or(bm, bitmap_mask(bit), ATOMIC_RELEASE);
}

static inline void
bitmap_clear(unsigned long *bm, int bit)
{
    if (bit >= LONG_BIT) {
        bitmap_lookup(&bm, &bit);
    }

    *bm &= ~bitmap_mask(bit);
}

static inline void
bitmap_clear_atomic(unsigned long *bm, int bit)
{
    if (bit >= LONG_BIT) {
        bitmap_lookup(&bm, &bit);
    }

    atomic_and(bm, ~bitmap_mask(bit), ATOMIC_RELEASE);
}

static inline int
bitmap_test(const unsigned long *bm, int bit)
{
    if (bit >= LONG_BIT) {
        bitmap_lookup(&bm, &bit);
    }

    return ((*bm & bitmap_mask(bit)) != 0);
}

static inline int
bitmap_test_atomic(const unsigned long *bm, int bit)
{
    if (bit >= LONG_BIT) {
        bitmap_lookup(&bm, &bit);
    }

    return ((atomic_load(bm, ATOMIC_ACQUIRE) & bitmap_mask(bit)) != 0);
}

static inline void
bitmap_and(unsigned long *a, const unsigned long *b, int nr_bits)
{
    int i, n;

    n = BITMAP_LONGS(nr_bits);

    for (i = 0; i < n; i++) {
        a[i] &= b[i];
    }
}

static inline void
bitmap_or(unsigned long *a, const unsigned long *b, int nr_bits)
{
    int i, n;

    n = BITMAP_LONGS(nr_bits);

    for (i = 0; i < n; i++) {
        a[i] |= b[i];
    }
}

static inline void
bitmap_xor(unsigned long *a, const unsigned long *b, int nr_bits)
{
    int i, n;

    n = BITMAP_LONGS(nr_bits);

    for (i = 0; i < n; i++) {
        a[i] ^= b[i];
    }
}

static inline int
bitmap_find_next(const unsigned long *bm, int nr_bits, int bit)
{
    return bitmap_find_next_bit(bm, nr_bits, bit, 0);
}

static inline int
bitmap_find_first(const unsigned long *bm, int nr_bits)
{
    return bitmap_find_next(bm, nr_bits, 0);
}

static inline int
bitmap_find_next_zero(const unsigned long *bm, int nr_bits, int bit)
{
    return bitmap_find_next_bit(bm, nr_bits, bit, 1);
}

static inline int
bitmap_find_first_zero(const unsigned long *bm, int nr_bits)
{
    return bitmap_find_next_zero(bm, nr_bits, 0);
}

static inline bool
bitmap_intersects(const unsigned long *a, const unsigned long *b, int nr_bits)
{
    int i, n;

    n = BITMAP_LONGS(nr_bits);

    for (i = 0; i < n; i++) {
        if (a[i] & b[i]) {
            return true;
        }
    }

    return false;
}

#define bitmap_for_each(bm, nr_bits, bit)                       \
for ((bit) = 0;                                                 \
     ((bit) < nr_bits)                                          \
     && (((bit) = bitmap_find_next(bm, nr_bits, bit)) != -1);   \
     (bit)++)

#define bitmap_for_each_zero(bm, nr_bits, bit)                      \
for ((bit) = 0;                                                     \
     ((bit) < nr_bits)                                              \
     && (((bit) = bitmap_find_next_zero(bm, nr_bits, bit)) != -1);  \
     (bit)++)

#endif /* KERN_BITMAP_H */
