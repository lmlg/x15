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

#include <machine/cpu.h>

#include <kern/atomic.h>
#include <kern/cbuf.h>
#include <kern/kuid.h>
#include <kern/panic.h>
#include <kern/rcu.h>
#include <kern/rdxtree.h>
#include <kern/spinlock.h>

struct kuid_map
{
  struct spinlock lock;
  struct rdxtree tree;
  uint32_t free_kuids[64];
  struct cbuf cbuf;
  int stamp;
  uint32_t max_id;
};

static struct kuid_map kuid_maps[KUID_MAX_CLS];

/* In order to prevent common bugs where the last used KUID
 * is recycled immediately, use at least this many newly created
 * KUID's before recycling. */
#define KUID_MAX_STAMP   16

static int
kuid_map_pop_key (struct kuid_map *map, rdxtree_key_t *keyp)
{
  uint32_t id;
  size_t size = sizeof (id);

  if (cbuf_pop (&map->cbuf, &id, &size) != 0)
    return (-1);

  map->stamp = 0;
  assert (size == sizeof (id));
  *keyp = id;
  return (0);
}

static int
kuid_map_alloc_key (struct kuid_map *map, struct kuid_head *head,
                    rdxtree_key_t *keyp)
{
  int error = rdxtree_insert_alloc (&map->tree, head, keyp);
  if (! error)
    ++map->stamp;

  return (error);
}

static int
kuid_map_alloc_radix (struct kuid_map *map, struct kuid_head *head,
                      rdxtree_key_t *keyp)
{
  if (map->stamp >= KUID_MAX_STAMP)
    return (kuid_map_pop_key (map, keyp) ?
            kuid_map_alloc_key (map, head, keyp) : 0);

  return (kuid_map_alloc_key (map, head, keyp) ?
          kuid_map_pop_key (map, keyp) : 0);
}

int
kuid_alloc (struct kuid_head *head, int cls)
{
  rdxtree_key_t key;
  assert ((size_t)cls < ARRAY_SIZE (kuid_maps));

  {
    _Auto map = &kuid_maps[cls];
    SPINLOCK_GUARD (&map->lock);

    if (kuid_map_alloc_radix (map, head, &key) != 0)
      return (EAGAIN);
    else if (key > map->max_id)
      {
        rdxtree_remove (&map->tree, key);
        return (EAGAIN);
      }
  }

  assert (key != 0);
  head->id = (uint32_t)key;
  return (0);
}

struct kuid_head*
kuid_find (uint32_t kuid, int cls)
{
  assert ((size_t)cls < ARRAY_SIZE (kuid_maps));
  _Auto map = &kuid_maps[cls];

  RCU_GUARD ();
  struct kuid_head *head = rdxtree_lookup (&map->tree, kuid);

  if (! head)
    return (head);

  while (1)
    {
      size_t nr_refs = atomic_load_rlx (&head->nr_refs);
      if (! nr_refs)
        return (NULL);
      else if (atomic_cas_bool_acq (&head->nr_refs, nr_refs, nr_refs + 1))
        return (head);

      cpu_pause ();
    }
}

int
kuid_remove (struct kuid_head *head, int cls)
{
  assert ((size_t)cls < ARRAY_SIZE (kuid_maps));

  if (!head->id)
    return (EINVAL);

  cpu_flags_t flags;
  _Auto map = &kuid_maps[cls];
  spinlock_lock_intr_save (&map->lock, &flags);

  struct kuid_head *prev = rdxtree_remove (&map->tree, head->id);
  if (prev)
    cbuf_push (&map->cbuf, &head->id, sizeof (head->id), false);

  spinlock_unlock_intr_restore (&map->lock, flags);
  return (!prev ? ESRCH : (prev != head ? EINVAL : 0));
}

static void
kuid_map_init (struct kuid_map *map, uint32_t max_id)
{
  spinlock_init (&map->lock);
  rdxtree_init (&map->tree, RDXTREE_KEY_ALLOC);
  cbuf_init (&map->cbuf, map->free_kuids, sizeof (map->free_kuids));
  map->max_id = max_id;

  // KUID 0 is reserved for kernel specific entities.
  if (rdxtree_insert (&map->tree, 0, &map->lock))
    panic ("could not reserve KUID 0");
}

static int __init
kuid_setup (void)
{
  kuid_map_init (&kuid_maps[KUID_TASK], (1u << 31) - 1);
  kuid_map_init (&kuid_maps[KUID_THREAD], (1u << 30) - 1);
  return (0);
}

INIT_OP_DEFINE (kuid_setup,
                INIT_OP_DEP (spinlock_setup, true),
                INIT_OP_DEP (rdxtree_setup, true));
