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
 * Common utilities for synchronization.
 */

#ifndef KERN_SYNC_H
#define KERN_SYNC_H

#include <stdint.h>
#include <string.h>

#include <kern/hash.h>
#include <kern/task.h>

struct vm_map;
struct vm_object;

union sync_key
{
  struct
    {
      struct vm_map *map;
      uintptr_t addr;
    } local;

  struct
    {
      struct vm_object *object;
      alignas (sizeof (uintptr_t)) uint64_t offset;
    } shared;

  struct
    {
      uintptr_t all[1 + sizeof (uint64_t) / sizeof (uintptr_t)];
    } both;
};

static_assert (sizeof (((union sync_key *)0)->both) >=
               sizeof (((union sync_key *)0)->local) &&
               sizeof (((union sync_key *)0)->both) >=
               sizeof (((union sync_key *)0)->shared),
               "invalid layout for sync_key::local");

static inline bool
sync_key_eq (const union sync_key *x, const union sync_key *y)
{
  for (size_t i = 0; i < ARRAY_SIZE (x->both.all); ++i)
    if (x->both.all[i] != y->both.all[i])
      return (false);

  return (true);
}

static inline uint32_t
sync_key_hash (const union sync_key *x)
{
  uint32_t ret = 0;
  for (size_t i = 0; i < ARRAY_SIZE (x->both.all); ++i)
    ret = hash_mix (ret, hash_uptr (x->both.all[i]));

  return (ret);
}

static inline void
sync_key_clear (union sync_key *key)
{
  for (size_t i = 0; i < ARRAY_SIZE (key->both.all); ++i)
    key->both.all[i] = 0;
}

static inline bool
sync_key_isclear (const union sync_key *key)
{
  for (size_t i = 0; i < ARRAY_SIZE (key->both.all); ++i)
    if (key->both.all[i] != 0)
      return (false);

  return (true);
}

static inline void
sync_key_init (union sync_key *key, const void *ptr)
{
  sync_key_clear (key);
  key->local.addr = (uintptr_t)ptr;
}

static inline void
sync_key_local_init (union sync_key *key, const void *ptr, struct vm_map *map)
{
  sync_key_init (key, ptr);
  key->local.map = map;
}

static inline void
sync_key_shared_init (union sync_key *key, struct vm_object *obj, uint64_t off)
{
  sync_key_clear (key);
  key->shared.object = obj;
  key->shared.offset = off;
}

#endif
