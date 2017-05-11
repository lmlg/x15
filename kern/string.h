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

#ifndef _KERN_STRING_H
#define _KERN_STRING_H

#include <stddef.h>

void * memcpy(void *dest, const void *src, size_t n);
void * memmove(void *dest, const void *src, size_t n);
void * memset(void *s, int c, size_t n);
int memcmp(const void *s1, const void *s2, size_t n);
size_t strlen(const char *s);
char * strcpy(char *dest, const char *src);
size_t strlcpy(char *dest, const char *src, size_t n);
int strcmp(const char *s1, const char *s2);
char * strchr(const char *s, int c);

#endif /* _KERN_STRING_H */
