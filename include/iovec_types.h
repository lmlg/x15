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

#ifndef UIO_TYPES_H
#define UIO_TYPES_H

#include <stddef.h>

/* Type for scatter/gather IO.
 * This structure must be in sync with user-space. */
struct iovec
{
  void *iov_base;
  size_t iov_len;
};

#define UIO_MAXIOV   1024   // Arbitrary, could be unlimited.

_Static_assert (__builtin_offsetof (struct iovec, iov_base) == 0 &&
                __builtin_offsetof (struct iovec, iov_len) == sizeof (void *),
                "Invalid offsets for struct iovec");

#endif
