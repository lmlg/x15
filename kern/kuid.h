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
 *
 * Kernel unique-id (KUID) management.
 */

#ifndef KERN_KUID_H
#define KERN_KUID_H

#include <stdint.h>

#include <kern/init.h>

enum
{
  KUID_TASK,
  KUID_THREAD,
  KUID_MAX_CLS
};

struct kuid_head
{
  uint32_t id;
  size_t nr_refs;
};

static inline void
kuid_head_init (struct kuid_head *head)
{
  head->id = 0;
  head->nr_refs = 1;
}

// Allocate a KUID of a particular class.
int kuid_alloc (struct kuid_head *head, int cls);

// Find the kuid structure that matches a numeric ID of a particular class.
struct kuid_head* kuid_find (uint32_t id, int cls);

// Remove a previously allocated KUID for a particular class.
int kuid_remove (struct kuid_head *kuid, int cls);

// Helper for types that embed a kuid structure.
#define kuid_find_type(id, type, member, cls)   \
  ({   \
     _Auto head_ = kuid_find (id, cls);   \
     head_ ? structof (head_, type, member) : 0;   \
   })

/*
 * This init operation provides :
 *  - KUID management operational.
 */
INIT_OP_DECLARE (kuid_setup);

#endif
