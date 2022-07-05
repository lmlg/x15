/*
 * Copyright (c) 2022 Agustina Arzille.
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

#ifndef STDINT_H
#define STDINT_H

#include <stddef.h>

/* This is a simplified implementation of the standard 'stdint' file.
 * The reason it exists is to provide definitions that can be managed
 * explicitly by the kernel when the standard presents ambiguities while
 * also leaving out unneeded stuff (i.e: the intXXXfast_t types). */

typedef __INT8_TYPE__ int8_t;
typedef __UINT8_TYPE__ uint8_t;

typedef __INT16_TYPE__ int16_t;
typedef __UINT16_TYPE__ uint16_t;

typedef int int32_t;
typedef unsigned int uint32_t;

typedef long long int64_t;
typedef unsigned long long uint64_t;

#define INT8_C       __INT8_C
#define INT16_C      __INT16_C
#define INT32_C      __INT32_C
#define INT64_C(x)   x ## ll

#define UINT8_C(x)    x
#define UINT16_C(x)   x
#define UINT32_C(x)   x ## u
#define UINT64_C(x)   x ## ull

#define INT8_MIN    (-128)
#define INT8_MAX    (0x7f)

#define INT16_MIN   (-32767 - 1)
#define INT16_MAX   (32767)

#define INT32_MIN   (-2147483647 - 1)
#define INT32_MAX   (2147483647)

#define INT64_MIN   (- INT64_C (9223372036854775807) - 1)
#define INT64_MAX   (INT64_C (9223372036854775807))

#define UINT8_MAX    (0xff)
#define UINT16_MAX   (0xffff)
#define UINT32_MAX   (UINT32_C (0xffffffff))
#define UINT64_MAX   (UINT64_C (0xffffffffffffffff))

typedef unsigned long uintptr_t;
typedef long intptr_t;

#if __WORDSIZE == 64
  #define UINTPTR_MAX   UINT64_MAX
  #define INTPTR_MIN    INT64_MIN
  #define INTPTR_MAX    INT64_MAX
#else
  #define UINTPTR_MAX   UINT32_MAX
  #define INTPTR_MIN    INT32_MIN
  #define INTPTR_MAX    INT32_MAX
#endif

#ifndef SIZE_MAX
  #define SIZE_MAX   UINTPTR_MAX
#endif

#endif
