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
#include <kern/signal.h>
#include <kern/slist.h>
#include <kern/user.h>
#include <kern/uthread.h>

static struct kmem_cache uthread_cache;

static void
uthread_ctor (void *tmp)
{
  struct uthread *ptr = tmp;
  memset (ptr, 0, sizeof (*ptr));

  ptr->sigaltstack.ss_flags = SS_DISABLE;
  futex_td_init (&ptr->futex_td);
  slist_init (&ptr->alloc_siginfo);
  mutex_init (&ptr->mutex);
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
  signal_uthr_dealloc (uthread);
  kmem_cache_free (&uthread_cache, uthread);
}

void
uthread_exit (struct uthread *uthread)
{
  if (uthread->tid && user_check_range (uthread->tid, sizeof (int)))
    futex_wake (uthread->tid, FUTEX_FLG_MUTATE | FUTEX_FLG_BROADCAST, 0);

  futex_td_exit (&uthread->futex_td);
}
