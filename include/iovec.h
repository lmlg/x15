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
 */

#ifndef UIO_H
#define UIO_H

#include <iovec_types.h>

#define IOVEC(base, len)   \
  (struct iovec) { .iov_base = (void *)(base), .iov_len = (len) }

static inline void
iovec_adv (struct iovec *iov, size_t off)
{
  iov->iov_base = (char *)iov->iov_base + off;
  iov->iov_len -= off;
}

#endif
