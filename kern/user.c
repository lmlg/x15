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
user_copy_impl (void *dst, const void *src, size_t size)
{
  struct unw_fixup fixup;
  int error = unw_fixup_save (&fixup);

  if (likely (! error))
    memcpy (dst, src, size);

  return (error);
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

static struct iovec*
user_iov_next (struct ipc_iov_iter *it, int check, int *errp)
{
  while (1)
    {
      if (it->head.iov_len)
        return (&it->head);
      else if (it->cur >= it->end)
        return (NULL);

      _Auto iov = it->begin + it->cur;
      if (check && !user_check_range (iov->iov_base, iov->iov_len))
        {
          *errp = -EFAULT;
          return (NULL);
        }

      it->head = *iov;
      ++it->cur;
    }
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
  int error = unw_fixup_save (&fixup);
  if (unlikely (error))
    return (-error);
  else if ((to_user && !user_check_iov_iter (dst)) ||
           (!to_user && !user_check_iov_iter (src)))
    return (-EFAULT);

  for (ssize_t ret = 0 ; ; )
    {
      struct iovec *dv = user_iov_next (dst, to_user, &error);
      if (! dv)
        return (error ?: ret);

      struct iovec *sv = user_iov_next (src, !to_user, &error);
      if (! sv)
        return (error ?: ret);

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
