/*
 * Copyright (c) 2012-2017 Richard Braun.
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

#ifndef KERN_STRING_H
#define KERN_STRING_H

#include <stddef.h>

#include <machine/string.h>

static inline void*
memcpy (void *restrict dst, const void *restrict src, size_t n)
{
#define MEMCPY_COMPTIME_TEST(size)   __builtin_constant_p (n) && n == size

#define MEMCPY_UNROLL(size)   \
  do   \
    {   \
      for (size_t i = 0; i < size; ++i)   \
        ((char *)dst)[i] = ((const char *)src)[i];   \
      return (dst);   \
    }   \
  while (0)

  if (MEMCPY_COMPTIME_TEST (1))
    *(char *)dst = *(const char *)src;
  else if (MEMCPY_COMPTIME_TEST (2))
    MEMCPY_UNROLL (2);
  else if (MEMCPY_COMPTIME_TEST (4))
    MEMCPY_UNROLL (4);
  else if (MEMCPY_COMPTIME_TEST (8))
    MEMCPY_UNROLL (8);

#if defined (STRING_ARCH_MEMCPY)
  return (STRING_ARCH_MEMCPY (dst, src, n));
#else
  for (size_t i = 0; i < n; ++i)
    ((char *)dst)[i] = ((const char *)src)[i];

  return (dst);
#endif

#undef MEMCPY_UNROLL
#undef MEMCPY_COMPTIME_TEST
}


static inline void*
memmove (void *restrict dst, const void *restrict src, size_t n)
{
#ifdef STRING_ARCH_MEMMOVE
  return (STRING_ARCH_MEMMOVE (dst, src, n));
#else
  if (dst <= src)
    return (memcpy (dst, src, n));

  char *dp = (char *)dst + n - 1;
  const char *sp = (const char *)src + n - 1;

  for (size_t i = 0; i < n; ++i)
    *dp-- = *sp--;

  return (dst);
#endif
}

static inline void*
memset (void *dst, int ch, size_t n)
{
#ifdef STRING_ARCH_MEMSET
  return (STRING_ARCH_MEMSET (dst, ch, n));
#else
  for (size_t i = 0; i < n; ++i)
    ((unsigned char *)dst)[i] = ch;

  return (dst);
#endif
}

int memcmp (const void *s1, const void *s2, size_t n);
void* memchr (const void *s, int c, size_t n);
size_t strlen (const char *s);
char* strcpy (char * restrict dest, const char *restrict src);
size_t strlcpy (char * restrict dest, const char * restrict src, size_t n);
int strcmp (const char *s1, const char *s2);
int strncmp (const char *s1, const char *s2, size_t n);
char* strchr (const char *s, int c);
const char* strerror (int error);

#endif
