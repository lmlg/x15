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

#include <assert.h>

#include <kern/capability.h>
#include <kern/kmem.h>
#include <kern/list.h>
#include <kern/signal.h>
#include <kern/slist.h>
#include <kern/user.h>
#include <kern/uthread.h>

#include <machine/cpu.h>

#include <vm/map.h>

struct uthread_cache_ops
{
  int (*alloc) (struct list *, uint32_t);
  void (*free) (struct list *);
};

static struct kmem_cache uthread_cache;

static const struct uthread_cache_ops uthread_cache_ops[] =
{
  [UTHR_CACHE_VME]  = { vm_map_cache_alloc, vm_map_cache_free },
  [UTHR_CACHE_LPAD] = { cap_lpad_cache_alloc, cap_lpad_cache_free },
};

static void
uthread_ctor (void *tmp)
{
  struct uthread *ptr = tmp;
  memset (ptr, 0, sizeof (*ptr));

  ptr->sigaltstack.ss_flags = SS_DISABLE;
  futex_td_init (&ptr->futex_td);
  slist_init (&ptr->alloc_siginfo);
  mutex_init (&ptr->mutex);
  for (int i = 0; i < UTHR_CACHE_NMAX; ++i)
    list_init (&ptr->cache.links[i]);
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
  for (int i = 0; i < UTHR_CACHE_NMAX; ++i)
    uthread_cache_ops[i].free (&uthread->cache.links[i]);

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

uintptr_t
uthread_get_sp (const struct uthread *uthread)
{
  return (cpu_exc_frame_sp (uthread->cpu_frame));
}

void
uthread_set_sp (struct uthread *uthread, uintptr_t sp)
{
  cpu_exc_frame_set_sp (uthread->cpu_frame, sp);
}

#define UTHR_CACHE_DFL_SIZE   4

void
uthread_cache_fill (struct uthread *uthread, int which)
{
  _Auto links = uthread->cache.links;

  if (which == UTHR_CACHE_ALL)
    for (int i = 0; i < UTHR_CACHE_NMAX; ++i)
      uthread_cache_ops[i].alloc (&links[i], UTHR_CACHE_DFL_SIZE);
  else
    {
      assert ((uint32_t)which < UTHR_CACHE_NMAX);
      uthread_cache_ops[which].alloc (&links[which], UTHR_CACHE_DFL_SIZE);
    }
}

struct list*
uthread_cache_pop (struct uthread *uthread, int which)
{
  assert ((uint32_t)which < UTHR_CACHE_NMAX);
  _Auto list = &uthread->cache.links[which];
  if (list_empty (list))
    return (NULL);

  _Auto ret = list_first (list);
  list_remove (ret);
  return (ret);
}

void
uthread_cache_push (struct uthread *uthread, int which, struct list *obj)
{
  assert ((uint32_t)which < UTHR_CACHE_NMAX);
  list_insert_tail (&uthread->cache.links[which], obj);
}
