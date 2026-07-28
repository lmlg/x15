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
 * Definitions for userspace threads.
 */

#ifndef KERN_UTHREAD_H
#define KERN_UTHREAD_H

#include <signal.h>
#include <stdint.h>

#include <kern/futex.h>
#include <kern/init.h>
#include <kern/list_types.h>
#include <kern/mutex.h>
#include <kern/slist_types.h>

struct cpu_exc_frame;

enum
{
  UTHR_CACHE_ALL = -1,
  UTHR_CACHE_VME,
  UTHR_CACHE_LPAD,
  UTHR_CACHE_NMAX,
};

struct uthread
{
  struct futex_td futex_td;
  int *tid;
  sigset_t sig_pending;
  sigset_t sig_mask;
  uintptr_t sig_saved_sp;
  uintptr_t sig_saved_altstack_sp;
  struct slist alloc_siginfo;
  struct mutex mutex;
  stack_t sigaltstack;
  uint8_t rtsig_count[SIGRTMAX - SIGRTMIN + 1];
  struct cpu_exc_frame *cpu_frame;
  struct
    {
      struct list links[UTHR_CACHE_NMAX];
    } cache;
};

static inline struct list*
uthread_get_cache_list (struct uthread *uthread, int which)
{
  return (&uthread->cache.links[which]);
}

// Allocate a new userspace thread structure.
struct uthread* uthread_allocate (void);

// Release the resources allocated for a userspace thread.
void uthread_free (struct uthread *uthread);

// De-initialize a userspace thread.
void uthread_exit (struct uthread *uthread);

// Manipulate a userspace object cache.
void uthread_cache_fill (struct uthread *uthread, int which);
struct list* uthread_cache_pop (struct uthread *uthread, int which);
void uthread_cache_push (struct uthread *uthread, int which, struct list *obj);

// Get or set the stack pointer of a user thread before the syscall/interrupt.
uintptr_t uthread_get_sp (const struct uthread *uthread);
void uthread_set_sp (struct uthread *uthread, uintptr_t sp);

#define uthread_self()   ((struct uthread *)thread_self()->uthread)

INIT_OP_DECLARE (uthread_setup);

#endif
