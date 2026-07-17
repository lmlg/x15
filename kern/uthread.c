/*
 * Copyright (c) 2026 Agustina Arzille.
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

#include <kern/kmem.h>
#include <kern/unwind.h>
#include <kern/user.h>
#include <kern/uthread.h>

static struct kmem_cache uthread_cache;

static void
uthread_ctor (void *tmp)
{
  _Auto ptr = (struct uthread *)tmp;
  ptr->tid = NULL;
  ptr->sig_pending = 0;
  ptr->sig_mask = 0;
  ptr->sig_saved_mask = 0;
  ptr->sig_saved_sp = 0;
  futex_td_init (&ptr->futex_td);
}

static int __init
uthread_setup (void)
{
  kmem_cache_init (&uthread_cache, "uthread", sizeof (struct uthread),
                   0, uthread_ctor, 0);
  return (0);
}

INIT_OP_DEFINE (uthread_setup);

struct uthread*
uthread_allocate (void)
{
  return (kmem_cache_alloc (&uthread_cache));
}

void
uthread_free (struct uthread *uthread)
{
  kmem_cache_free (&uthread_cache, uthread);
}

void
uthread_exit (struct uthread *uthread)
{
  if (uthread->tid && user_check_range (uthread->tid, sizeof (int)))
    {
      struct unw_fixup fixup;
      if (unw_fixup_save (&fixup) == 0)
        {
          atomic_store_rel (uthread->tid, 0);
          futex_wake (uthread->tid, FUTEX_FLG_BROADCAST, 0);
        }
    }

  futex_td_exit (&uthread->futex_td);
}
