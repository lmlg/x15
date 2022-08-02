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

struct kuid_data
{
  struct spinlock lock;
  struct rdxtree tree;
  uint32_t free_kuids[64];
  struct cbuf cbuf;
};

static int
kuid_data_pop_key (struct kuid_data *data, rdxtree_key_t *keyp)
{
  uint32_t id;
  size_t size = sizeof (id);

  if (cbuf_pop (&data->cbuf, &id, &size) != 0)
    return (0);

  *keyp = id;
  return (1);
}

static struct kuid_data kuid_data;

int
kuid_alloc (struct kuid_head *head, uint32_t max_id)
{
  rdxtree_key_t key;

  {
    _Auto data = &kuid_data;

    SPINLOCK_GUARD (&data->lock, false);
    int popped_key = kuid_data_pop_key (data, &key),
        error = popped_key ? rdxtree_insert (&data->tree, key, head) :
                             rdxtree_insert_alloc (&data->tree, head, &key);

    if (error)
      {
      error:
        if (popped_key)
          cbuf_push (&data->cbuf, &key, sizeof (key), false);
        return (error);
      }
    else if (key > max_id)
      {
        rdxtree_remove (&data->tree, key);
        error = EAGAIN;
        goto error;
      }
  }

  assert (key != 0);
  head->id = (uint32_t)key;
  return (0);
}

struct kuid_head*
kuid_find (uint32_t kuid)
{
  RCU_GUARD ();
  struct kuid_head *head = rdxtree_lookup (&kuid_data.tree, kuid);

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
kuid_remove (struct kuid_head *head)
{
  if (!head->id)
    return (EINVAL);

  cpu_flags_t flags;
  _Auto data = &kuid_data;
  spinlock_lock_intr_save (&data->lock, &flags);

  struct kuid_head *prev = rdxtree_remove (&data->tree, head->id);
  if (prev)
    cbuf_push (&data->cbuf, &head->id, sizeof (head->id), false);

  spinlock_unlock_intr_restore (&data->lock, flags);
  return (!prev ? ESRCH : (prev != head ? EINVAL : 0));
}

static int __init
kuid_setup (void)
{
  _Auto data = &kuid_data;

  spinlock_init (&data->lock);
  rdxtree_init (&data->tree, RDXTREE_KEY_ALLOC);
  cbuf_init (&data->cbuf, data->free_kuids, sizeof (data->free_kuids));

  // KUID 0 is reserved for kernel specific entities.
  int error = rdxtree_insert (&data->tree, 0, &data->lock);
  if (error)
    panic ("could not reserve KUID 0");

  return (0);
}

INIT_OP_DEFINE (kuid_setup,
                INIT_OP_DEP (spinlock_setup, true),
                INIT_OP_DEP (rdxtree_setup, true));
