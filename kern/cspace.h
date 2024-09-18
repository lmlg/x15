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
 * Capability spaces.
*/

#ifndef KERN_CAP_SPACE_H
#define KERN_CAP_SPACE_H

#include <errno.h>

#include <kern/capability.h>
#include <kern/cspace_types.h>
#include <kern/rcu.h>

#define CSPACE_WEAK   0x02   // Use a weak reference for a capability.

#define CSPACE_MASK   (CSPACE_WEAK)

static inline void
cspace_init (struct cspace *sp)
{
  rdxtree_init (&sp->tree, RDXTREE_KEY_ALLOC);
  adaptive_lock_init (&sp->lock);
}

static inline void
cspace_maybe_rel (void *ptr)
{
  if (!((uintptr_t)ptr & RDXTREE_XBIT))
    cap_base_rel (ptr);
}

static inline struct cap_base*
cspace_get_all (struct cspace *sp, int capx, int *marked)
{
  if (capx < 0)
    return (NULL);

  CPU_INTR_GUARD ();
  RCU_GUARD ();

  void *ptr = rdxtree_lookup (&sp->tree, capx);
  if (! ptr)
    return (ptr);

  *marked = ((uintptr_t)ptr & RDXTREE_XBIT) != 0;
  struct cap_base *cap = (void *)((uintptr_t)ptr & ~RDXTREE_XBIT);
  cap_base_acq (cap);
  return (cap);
}

static inline struct cap_base*
cspace_get (struct cspace *sp, int capx)
{
  int marked;
  return (cspace_get_all (sp, capx, &marked));
}

static inline int
cspace_add_free_locked (struct cspace *sp, struct cap_base *cap,
                        uint32_t flags)
{
  rdxtree_key_t cap_idx;
  void *ptr = (void *)((uintptr_t)cap |
              ((flags & CSPACE_WEAK) ? RDXTREE_XBIT : 0));
  int rv = rdxtree_insert_alloc (&sp->tree, ptr, &cap_idx);
  if (rv < 0)
    return (-ENOMEM);

  cap_base_acq (cap);
  return ((int)cap_idx);
}

static inline int
cspace_add_free (struct cspace *sp, struct cap_base *cap, uint32_t flags)
{
  ADAPTIVE_LOCK_GUARD (&sp->lock);
  return (cspace_add_free_locked (sp, cap, flags));
}

static inline int
cspace_rem_locked (struct cspace *sp, int cap_idx)
{
  if (cap_idx < 0)
    return (EBADF);

  void *ptr = rdxtree_remove (&sp->tree, cap_idx);
  if (! ptr)
    return (EINVAL);
  else if (!((uintptr_t)ptr & RDXTREE_XBIT))
    {
      CPU_INTR_GUARD ();
      cap_base_rel (ptr);
    }

  return (0);
}

static inline int
cspace_rem (struct cspace *sp, int cap_idx)
{
  ADAPTIVE_LOCK_GUARD (&sp->lock);
  return (cspace_rem_locked (sp, cap_idx));
}

static inline int
cspace_dup (struct cspace *sp, int cap_idx)
{
  _Auto cap = cspace_get (sp, cap_idx);
  if (! cap)
    return (-EBADF);

  int new_idx = cspace_add_free (sp, cap, 0);
  cap_base_rel (cap);
  return (new_idx);
}

static inline int
cspace_dup3 (struct cspace *sp, int cap_idx, int new_idx,
             uint32_t flags __unused)
{
  if (cap_idx < 0)
    return (EBADF);

  ADAPTIVE_LOCK_GUARD (&sp->lock);
  struct cap_base *cap = rdxtree_lookup (&sp->tree, cap_idx);

  if (! cap)
    return (EBADF);

  void **slot;
  int rv = rdxtree_insert_slot (&sp->tree, new_idx, cap, &slot);

  if (rv == EBUSY)
    // Replace the older capability.
    cspace_maybe_rel (rdxtree_replace_slot (slot, cap));
  else if (rv)
    return (ENOMEM);

  cap_base_acq (cap);
  return (0);
}

static inline void
cspace_destroy (struct cspace *sp)
{
  struct rdxtree_iter iter;
  void *cap;

  rdxtree_for_each (&sp->tree, &iter, cap)
    cspace_maybe_rel (cap);

  rdxtree_remove_all (&sp->tree);
}

#define cspace_self()   ((struct cspace *)&thread_self()->xtask->caps)

#endif
