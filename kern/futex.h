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
 * Futexes: Building block for user-space synchronization primitives.
 */

#ifndef KERN_FUTEX_H
#define KERN_FUTEX_H

#include <futex.h>
#include <stdint.h>

#include <kern/syscall_i.h>

struct futex_td
{
  struct futex_robust_list *pending;
  struct futex_robust_list *list;
};

static inline void
futex_td_init (struct futex_td *td)
{
  td->pending = td->list = NULL;
}

/*
 * Wait for a 'futex_wake' on this address, checking before that
 * it containts the specified value (failing with EAGAIN otherwise).
 * If flags hast the 'FUTEX_FLG_TIMED' set, wait no more than the specified
 * timeout, and fail with ETIMEDOUT if no wake call was done.
 */
int futex_wait (int *addr, int value, uint32_t flags, uint64_t ticks);

/*
 * Wake up threads waiting on an address. Either one thread (default) or
 * all threads (if FUTEX_FLG_BROADCAST is set) may be woken up. In addition,
 * if the FUTEX_FLG_MUTATE bit is set, the address' contents may be set to
 * a specified value (useful for robust futexes).
 */
int futex_wake (int *addr, uint32_t flags, int value);

/*
 * Move waiters sleeping on one futex to another one, optionally waking
 * up a waiter in the process. If FUTEX_FLG_BROADCAST is set in flags, moves
 * all waiters; otherwise only one is moved.
 *
 * This function is not implemented for PI futexes.
 */
int futex_requeue (int *dst_addr, int *src_addr,
                   int wake_one, uint32_t flags);

// Clean up all held robust futexes by the calling thread.
void futex_td_exit (struct futex_td *td);

// Syscall entry point for futex.
SYSCALL_DECL (futex);

#endif
