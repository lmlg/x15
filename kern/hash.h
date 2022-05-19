/*
 * Copyright (c) 2010-2017 Richard Braun.
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
 * Hash functions for integers and strings.
 *
 * Integer hashing follows Thomas Wang's paper about his 32/64-bits mix
 * functions :
 * - https://gist.github.com/badboy/6267743
 *
 * String hashing uses a variant of the djb2 algorithm with k=31, as in
 * the implementation of the hashCode() method of the Java String class :
 * - http://www.javamex.com/tutorials/collections/hash_function_technical.shtml
 *
 * Note that this algorithm isn't suitable to obtain usable 64-bits hashes
 * and is expected to only serve as an array index producer.
 *
 * These functions all have a bits parameter that indicates the number of
 * relevant bits the caller is interested in. When returning a hash, its
 * value must be truncated so that it can fit in the requested bit size.
 * It can be used by the implementation to select high or low bits, depending
 * on their relative randomness. To get complete, unmasked hashes, use the
 * HASH_ALLBITS macro.
 */

#ifndef KERN_HASH_H
#define KERN_HASH_H

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __LP64__
  #define HASH_ALLBITS   64
  #define hash_long      hash_int64
#else
  static_assert (sizeof (long) == 4, "unsupported data model");
  #define HASH_ALLBITS   32
  #define hash_long      hash_int32
#endif

static inline bool
hash_bits_valid (unsigned int bits)
{
  return (bits && bits <= HASH_ALLBITS);
}

static inline uint32_t
hash_int32 (uint32_t n, unsigned int bits)
{
  assert (hash_bits_valid (bits));

  uint32_t hash = n;
  hash = ~hash + (hash << 15);
  hash ^= (hash >> 12);
  hash += (hash << 2);
  hash ^= (hash >> 4);
  hash += (hash << 3) + (hash << 11);
  hash ^= (hash >> 16);

  return (hash >> (32 - bits));
}

static inline uint64_t
hash_int64 (uint64_t n, unsigned int bits)
{
  assert (hash_bits_valid (bits));

  uint64_t hash = n;
  hash = ~hash + (hash << 21);
  hash ^= (hash >> 24);
  hash += (hash << 3) + (hash << 8);
  hash ^= (hash >> 14);
  hash += (hash << 2) + (hash << 4);
  hash ^= (hash >> 28);
  hash += (hash << 31);

  return (hash >> (64 - bits));
}

static inline uintptr_t
hash_ptr (const void *ptr, unsigned int bits)
{
#ifdef __LP64__
  return (hash_int64 ((uintptr_t) ptr, bits));
#else
  return (hash_int32 ((uintptr_t) ptr, bits));
#endif
}

static inline unsigned long
hash_str (const char *str, unsigned int bits)
{
  assert (hash_bits_valid (bits));

  uintptr_t hash;
  for (hash = 0; /* no condition */ ; str++)
    {
      int c = *str;
      if (! c)
        break;

      hash = ((hash << 5) - hash) + c;
    }

  /*
   * This mask construction avoids the undefined behavior that would
   * result from directly shifting by the number of bits, if that number
   * is equal to the width of the hash.
   */
  uintptr_t mask = (~0UL >> (HASH_ALLBITS - bits));
  return (hash & mask);
}

#endif
