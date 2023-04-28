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
  if (!user_check_addr (udst))
    return (-EFAULT);

  return (user_copy_impl (udst, src, size));
}

int
user_copy_from (void *dst, const void *usrc, size_t size)
{
  if (!user_check_addr (usrc))
    return (-EFAULT);

  return (user_copy_impl (dst, usrc, size));
}

static ssize_t
user_copyv_impl (struct iovec *dst, uint32_t nr_dst,
                 const struct iovec *src, uint32_t nr_src, int to_user)
{
  struct unw_fixup fixup;
  int error = unw_fixup_save (&fixup);
  if (unlikely (error))
    return (error);

  struct iovec dv = IOVEC (0, 0), sv = IOVEC (0, 0);
  ssize_t ret = 0;

  while (1)
    {
      if (!dv.iov_len)
        {
          if (! nr_dst)
            return (ret);

          dv = *dst++;
          --nr_dst;
        }

      if (!sv.iov_len)
        {
          if (! nr_src)
            return (ret);

          sv = *src++;
          --nr_src;
        }

      if ((to_user && !user_check_addr (dv.iov_base)) ||
          (!to_user && !user_check_addr (sv.iov_base)))
        return (-EFAULT);

      size_t tmp = MIN (dv.iov_len, sv.iov_len);
      memcpy (dv.iov_base, sv.iov_base, tmp);

      iovec_adv (&dv, tmp);
      iovec_adv (&sv, tmp);
      ret += tmp;
    }
}

ssize_t
user_copyv_to (struct iovec *udst, uint32_t nr_dst,
               const struct iovec *src, uint32_t nr_src)
{
  return (user_copyv_impl (udst, nr_dst, src, nr_src, 1));
}

ssize_t
user_copyv_from (struct iovec *dst, uint32_t nr_dst,
                 const struct iovec *usrc, uint32_t nr_src)
{
  return (user_copyv_impl (dst, nr_dst, usrc, nr_src, 0));
}
