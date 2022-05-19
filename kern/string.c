/*
 * Copyright (c) 2012-2019 Richard Braun.
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
 *
 * Trivial, portable implementations.
 */

#include <errno.h>
#include <stddef.h>
#include <string.h>

#include <kern/macros.h>
#include <machine/string.h>

#ifndef STRING_ARCH_MEMCPY

void*
memcpy (void *dest, const void *src, size_t n)
{
  char *dest_ptr = dest;
  const char *src_ptr = src;

  for (size_t i = 0; i < n; i++)
    *dest_ptr++ = *src_ptr++;

  return (dest);
}

#endif

#ifndef STRING_ARCH_MEMMOVE

void*
memmove (void *dest, const void *src, size_t n)
{
  if (dest <= src)
    return (memcpy (dest, src, n));
  
  char *dest_ptr = dest + n - 1;
  const char *src_ptr = src + n - 1;

  for (size_t i = 0; i < n; i++)
    *--dest_ptr = *--src_ptr;

  return (dest);
}

#endif

#ifndef STRING_ARCH_MEMSET

void*
memset (void *s, int c, size_t n)
{
  for (size_t i = 0; i < n; ++i)
    ((unsigned char *)s)[i] = c;

  return (s);
}

#endif

#ifndef STRING_ARCH_MEMCMP

int
memcmp (const void *s1, const void *s2, size_t n)
{
  const unsigned char *a1 = s1, *a2 = s2;
  for (size_t i = 0; i < n; i++)
    if (a1[i] != a2[i])
      return ((int)a1[i] - (int)a2[i]);

  return (0);
}

#endif

#ifndef STRING_ARCH_STRLEN

size_t
strlen (const char *s)
{
  const char *start = s;
  for (; *s; ++s) 
    ;

  return (s - start);
}

#endif

#ifndef STRING_ARCH_STRCPY

char *
strcpy (char *dest, const char *src)
{
  char *tmp = dest;
  while (*dest++ = *src++)
    ;
  return (tmp);
}
#endif

size_t
strlcpy (char *dest, const char *src, size_t n)
{
  size_t len = strlen (src);
  if (! n)
    return (len);

  n = len < n ? len : n - 1;
  memcpy (dest, src, n);
  dest[n] = '\0';
  return len;
}

#ifndef STRING_ARCH_STRCMP

int
strcmp (const char *s1, const char *s2)
{
  char c1, c2;
  for (; (c1 = *s1) == (c2 = *s2); ++s1, ++s2)
    if (! c1)
      return (0);

  // See C11 7.24.4 Comparison functions.
  return ((int)(unsigned char)c1 - (int)(unsigned char)c2);
}
#endif

#ifndef STRING_ARCH_STRNCMP

int
strncmp (const char *s1, const char *s2, size_t n)
{
  if (unlikely (! n))
    return (0);

  char c1, c2;
  for (; n && (c1 = *s1) == (c2 = *s2); --n, ++s1, ++s2)
    if (! c1)
      return (0);

  // See C11 7.24.4 Comparison functions */
  return ((int) (unsigned char)c1 - (int)(unsigned char)c2);
}

#endif

#ifndef STRING_ARCH_STRCHR

char*
strchr (const char *s, int c)
{
  for ( ; ; ++s)
    if (*s == c)
      return ((char *)s);
    else if (*s == '\0')
      return (NULL);
}

#endif

const char*
strerror (int error)
{
  switch (error)
    {
      case 0:
        return ("success");
      case ENOMEM:
        return ("out of memory");
      case EAGAIN:
        return ("resource temporarily unavailable");
      case EINVAL:
        return ("invalid argument");
      case EBUSY:
        return ("device or resource busy");
      case EFAULT:
        return ("bad address");
      case ENODEV:
        return ("no such device");
      case EEXIST:
        return ("entry exists");
      case EIO:
        return ("input/output error");
      case ESRCH:
        return ("no such process");
      case ETIMEDOUT:
        return ("timeout error");
      case ENOENT:
        return ("no such file or directory");
      case EOVERFLOW:
        return ("value too large to be stored in data type");
      case EMSGSIZE:
        return ("message too long");
      default:
        return ("unknown error");
    }
}
