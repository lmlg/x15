/*
 * Copyright (c) 2024 Agustina Arzille.
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
 * Definitions for kernel messages.
 */

#ifndef KERN_KMSG_H
#define KERN_KMSG_H   1

#include <stdint.h>

enum
{
  KMSG_TYPE_PAGE_REQ = 1,
  KMSG_TYPE_MMAP_REQ,
};

struct kmessage
{
  int type;
  int msg_flags;
  union
    {
      struct
        {
          uint64_t start;
          uint64_t end;
        } page_req;

      struct
        {
          uintptr_t tag;
          uint64_t offset;
          int prot;
          int flags;
        } mmap_req;
    };
};

#endif
