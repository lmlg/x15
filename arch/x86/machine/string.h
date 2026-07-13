/*
 * Copyright (c) 2017 Richard Braun.
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

#ifndef X86_STRING_H
#define X86_STRING_H

// Provide architecture-specific string functions.
#define STRING_ARCH_MEMCPY(D, S, N)   \
  ({   \
     void *orig_ = (D), *dst_ = orig_;   \
     asm volatile ("rep movsb" : "+D" (dst_), "+S" (S), "+c" (N)   \
                   : : "memory");   \
     orig_;   \
   })

#define STRING_ARCH_MEMMOVE(D, S, N)   \
  ({   \
     void *orig_ = (D), *dst_ = orig_;   \
     const void *src_ = (S);   \
     if (dst_ <= src_)   \
       asm volatile ("rep movsb" : "+D" (dst_), "+S" (src_), "+c" (N)   \
                     : : "memory");   \
     else   \
       {   \
         size_t n_ = (N);   \
         dst_ = (char *)dst_ + n_ - 1;   \
         src_ = (const char *)src_ + n_ - 1;   \
         asm volatile ("std; rep movsb; cld"   \
                       : "+D" (dst_), "+S" (src_), "+c" (n_) : : "memory");   \
       }   \
     orig_;   \
   })

#define STRING_ARCH_MEMSET(S, C, N)   \
  ({   \
     void *orig_ = (S), *dst_ = orig_;   \
     asm volatile ("rep stosb"   \
                   : "+D" (dst_), "+c" (N) : "a" (C) : "memory");   \
     orig_;   \
   })

#define STRING_ARCH_MEMCMP
#define STRING_ARCH_STRLEN
#define STRING_ARCH_STRCPY
#define STRING_ARCH_STRCMP
#define STRING_ARCH_STRNCMP
#define STRING_ARCH_STRCHR

#endif
