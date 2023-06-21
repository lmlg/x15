/*
 * Copyright (c) 2023 Agustina Arzille.
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
 * Hash functions for integers and byte strings.
 *
 * Integer hashing functions are based on this article by Chris Wellons:
 * https://nullprogram.com/blog/2018/07/31/
 *
 * String hashing is based on Bruno Haible's implementation:
 * https://www.haible.de/bruno/hashfunc.html
 *
 */

#ifndef KERN_HASH_H
#define KERN_HASH_H

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

static inline uint32_t
hash_bytes (const void *ptr, size_t len)
{
  uint32_t ret = (uint32_t)len;
  for (size_t i = 0; i < len; ++i)
    {
      ret = (ret << 9) | (ret >> 23);
      ret += ((const unsigned char *)ptr)[i];
    }

  return (ret ?: ~(uint32_t)0);
}

static inline uint32_t
hash_mix (uint32_t h1, uint32_t h2)
{
  uint32_t next = (h1 << 5) | (h1 >> 27);
  return (next ^ h2);
}

static inline uint32_t
hash_u32 (uint32_t x)
{
  x ^= x >> 16;
  x *= 0x21f0aaad;
  x ^= x >> 15;
  x *= 0x735a2d97;
  x ^= x >> 15;
  return (x);
}

static inline uint32_t
hash_u64 (uint64_t x)
{
  uint32_t lo = (uint32_t)x, hi = (uint32_t)(x >> 32);
  return (hash_mix (hash_u32 (lo), hash_u32 (hi)));
}

static inline uint32_t
hash_uptr (uintptr_t x)
{
#ifdef __LP64__
  return (hash_u64 (x));
#else
  return (hash_u32 (x));
#endif
}

#endif
