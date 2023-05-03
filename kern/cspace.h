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

static inline void
cspace_init (struct cspace *sp)
{
  rdxtree_init (&sp->tree, RDXTREE_KEY_ALLOC);
  adaptive_lock_init (&sp->lock);
}

static inline struct cap_base*
cspace_get (struct cspace *sp, int cap_idx)
{
  if (cap_idx < 0)
    return (NULL);

  CPU_INTR_GUARD ();
  RCU_GUARD ();

  struct cap_base *cap = rdxtree_lookup (&sp->tree, cap_idx);
  if (cap)
    cap_base_acq (cap);

  return (cap);
}

static inline int
cspace_add_free_locked (struct cspace *sp, struct cap_base *cap,
                        int flags __unused)
{
  rdxtree_key_t cap_idx;
  int rv = rdxtree_insert_alloc (&sp->tree, cap, &cap_idx);
  if (rv < 0)
    return (-ENOMEM);

  cap_base_acq (cap);
  return ((int)cap_idx);
}

static inline int
cspace_add_free (struct cspace *sp, struct cap_base *cap,
                 int flags __unused)
{
  ADAPTIVE_LOCK_GUARD (&sp->lock);
  return (cspace_add_free_locked (sp, cap, flags));
}

static inline int
cspace_rem_locked (struct cspace *sp, int cap_idx)
{
  if (cap_idx < 0)
    return (EBADF);

  struct cap_base *cap = rdxtree_remove (&sp->tree, cap_idx);
  if (! cap)
    return (EINVAL);

  CPU_INTR_GUARD ();
  cap_base_rel (cap);
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
  if (new_idx < 0)
    cap_base_rel (cap);

  return (new_idx);
}

static inline int
cspace_dup3 (struct cspace *sp, int cap_idx, int new_idx,
             int flags __unused)
{
  if (cap_idx < 0)
    return (-EBADF);

  ADAPTIVE_LOCK_GUARD (&sp->lock);
  struct cap_base *cap = rdxtree_lookup (&sp->tree, cap_idx);

  if (! cap)
    return (-EBADF);

  void **slot;
  int rv = rdxtree_insert_slot (&sp->tree, new_idx, cap, &slot);

  if (rv == EBUSY)
    // Release the older capability.
    cap_base_rel (rdxtree_replace_slot (slot, cap));
  else if (rv)
    {
      cap_base_rel (cap);
      return (-ENOMEM);
    }

  cap_base_acq (cap);
  return (0);
}

static inline void
cspace_destroy (struct cspace *sp)
{
  struct rdxtree_iter iter;
  struct cap_base *cap;

  rdxtree_for_each (&sp->tree, &iter, cap)
    cap_base_rel (cap);

  rdxtree_remove_all (&sp->tree);
}

#define cspace_self()   ((struct cspace *)&thread_self()->task->caps)

#endif
