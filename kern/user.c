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
 */

#include <iovec.h>

#include <kern/ipc.h>
#include <kern/unwind.h>
#include <kern/user.h>

static int
user_copy_impl (char *dst, const char *src, size_t size)
{
  struct unw_fixup fixup;
  int error = unw_fixup_save (&fixup);

  if (unlikely (error))
    return (error);

#define user_ua_cpy(sz)   \
  ((union user_ua *)dst)->u##sz = ((const union user_ua *)src)->u##sz

  switch (size)
    {
      case 0:
        return (0);

      case 3:
        dst[2] = src[2];
        __fallthrough;
      case 2:
        user_ua_cpy (2);
        break;

      case 1:
        dst[0] = src[0];
        break;

      case 7:
        dst[6] = src[6];
        __fallthrough;
      case 6:
        user_ua_cpy (4);
        dst += 4, src += 4;
        user_ua_cpy (2);
        break;

      case 5:
        dst[4] = src[4];
        __fallthrough;
      case 4:
        user_ua_cpy (4);
        break;

      case 8:
        user_ua_cpy (8);
        break;

#undef user_ua_cpy

      default:
        memcpy (dst, src, size);
    }

  return (0);
}

int
user_copy_to (void *udst, const void *src, size_t size)
{
  return (user_check_range (udst, size) ?
          user_copy_impl (udst, src, size) : EFAULT);
}

int
user_copy_from (void *dst, const void *usrc, size_t size)
{
  return (user_check_range (usrc, size) ?
          user_copy_impl (dst, usrc, size) : EFAULT);
}

static bool
user_check_iov_iter (struct ipc_iov_iter *iov)
{
  return (iov->begin == &iov->head ||
          user_check_range (iov->begin, iov->end * sizeof (*iov->begin)));
}

ssize_t
user_copyv_impl (struct ipc_iov_iter *dst,
                 struct ipc_iov_iter *src, int to_user)
{
  struct unw_fixup fixup;
  ssize_t ret = unw_fixup_save (&fixup);
  if (unlikely (ret))
    return (-ret);
  else if (!user_check_iov_iter (to_user ? dst : src))
    return (-EFAULT);

  ssize_t *err1 = to_user ? &ret : NULL;
  ssize_t *err2 = to_user ? NULL : &ret;

  while (1)
    {
      struct iovec *dv = ipc_iov_iter_usrnext (dst, err1);
      if (! dv)
        return (ret);

      struct iovec *sv = ipc_iov_iter_usrnext (src, err2);
      if (! sv)
        return (ret);

      size_t nbytes = MIN (dv->iov_len, sv->iov_len);
      if (unlikely ((ret += nbytes) < 0))
        return (-EOVERFLOW);

      memcpy (dv->iov_base, sv->iov_base, nbytes);
      iovec_adv (dv, nbytes);
      iovec_adv (sv, nbytes);
    }
}

ssize_t
user_copyv_to (struct ipc_iov_iter *udst, struct ipc_iov_iter *src)
{
  return (user_copyv_impl (udst, src, 1));
}

ssize_t
user_copyv_from (struct ipc_iov_iter *dst, struct ipc_iov_iter *usrc)
{
  return (user_copyv_impl (dst, usrc, 0));
}

int
user_read_struct (void *dst, const void *usrc, size_t size)
{
  if (!user_check_range (usrc, sizeof (uint32_t)))
    return (EFAULT);

  struct unw_fixup fixup;
  int error = unw_fixup_save (&fixup);

  if (unlikely (error))
    return (error);

  size_t rsize = ((const union user_ua *)usrc)->u4;
  if (size < rsize)
    rsize = size;

  if (!user_check_range (usrc, rsize))
    return (EFAULT);

  *(uint32_t *)dst = rsize;
  user_copy_impl ((char *)dst + sizeof (uint32_t),
                  (const char *)usrc + sizeof (uint32_t),
                  rsize - sizeof (uint32_t));
  return (0);
}

int
user_write_struct (void *udst, const void *src, size_t size)
{
  if (!user_check_range (udst, sizeof (uint32_t)))
    return (EFAULT);

  struct unw_fixup fixup;
  int error = unw_fixup_save (&fixup);

  if (unlikely (error))
    return (error);

  size_t rsize = ((const union user_ua *)udst)->u4;
  if (size < rsize)
    rsize = size;

  if (!user_check_range (udst, rsize))
    return (EFAULT);

  *(uint32_t *)udst = rsize;
  user_copy_impl ((char *)udst + sizeof (uint32_t),
                  (const char *)src + sizeof (uint32_t),
                  rsize - sizeof (uint32_t));
  return (0);
}
