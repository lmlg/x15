/*
 * Copyright (c) 2012 Richard Braun.
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

#include <lib/stddef.h>
#include <lib/string.h>

void *
memcpy(void *dest, const void *src, size_t n)
{
    const char *src_ptr;
    char *dest_ptr;
    size_t i;

    dest_ptr = dest;
    src_ptr = src;

    for (i = 0; i < n; i++)
        *dest_ptr++ = *src_ptr++;

    return dest;
}

void *
memmove(void *dest, const void *src, size_t n)
{
    const char *src_ptr;
    char *dest_ptr;
    size_t i;

    if (src == dest)
        return dest;
    else if (src < dest) {
        dest_ptr = (char *)dest + n - 1;
        src_ptr = (const char *)src + n - 1;

        for (i = 0; i < n; i++)
            *dest_ptr-- = *src_ptr--;
    } else if (src > dest) {
        dest_ptr = dest;
        src_ptr = src;

        for  (i = 0; i < n; i++)
            *dest_ptr++ = *src_ptr++;
    }

    return dest;
}

void *
memset(void *s, int c, size_t n)
{
    char *buffer;
    size_t i;

    buffer = s;

    for (i = 0; i < n; i++)
        buffer[i] = c;

    return s;
}

int
memcmp(const void *s1, const void *s2, size_t n)
{
    const char *a1, *a2;
    size_t i;

    a1 = s1;
    a2 = s2;

    for (i = 0; i < n; i++)
        if (a1[i] != a2[i])
            return a2[i] - a1[i];

    return 0;
}

size_t
strlen(const char *s)
{
    size_t i;

    i = 0;

    while (*s++ != '\0')
        i++;

    return i;
}

char *
strcpy(char *dest, const char *src)
{
    char *tmp;

    tmp = dest;

    while ((*dest = *src) != '\0') {
        dest++;
        src++;
    }

    return tmp;
}

int
strcmp(const char *s1, const char *s2)
{
    char c1, c2;

    while ((c1 = *s1) == (c2 = *s2)) {
        if (c1 == '\0')
            return 0;

        s1++;
        s2++;
    }

    return (c1 < c2) ? -1 : 1;
}