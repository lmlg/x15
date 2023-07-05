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

#include <assert.h>
#include <stdint.h>

#define FUTEX_SHARED      0x01   // Futex may be shared across tasks.
#define FUTEX_TIMED       0x02   // Wait is time bound.
#define FUTEX_MUTATE      0x04   // Change the futex contents before waking.
#define FUTEX_BROADCAST   0x08   // Wake all waiters, or move all waiters.
#define FUTEX_ABSTIME     0x10   // Time passed is an absolute value.
#define FUTEX_PI          0x20   // Futex has priority-inheritance semantics.

struct futex_robust_list
{
  int futex;
  int flags;
  uint64_t next __attribute__ ((aligned (8)));
};

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

// Bits used in the futex word for PI and robust futexes.
#define FUTEX_WAITERS      (1u << 31)
#define FUTEX_OWNER_DIED   (1u << 30)
#define FUTEX_TID_MASK     (~(FUTEX_WAITERS | FUTEX_OWNER_DIED))

// Ensure binary layout is correct.
static_assert (sizeof (struct futex_robust_list) == 16,
               "invalid size for futex_robust_list");

static_assert (__builtin_offsetof (struct futex_robust_list, next) == 8,
               "invalid layout for futex_robust_list");

/*
 * Wait for a 'futex_wake' on this address, checking before that
 * it containts the specified value (failing with EAGAIN otherwise).
 * If flags hast the 'FUTEX_TIMED' set, wait no more than the specified
 * timeout, and fail with ETIMEDOUT if no wake call was done.
 */
int futex_wait (int *addr, int value, uint32_t flags, uint64_t ticks);

/*
 * Wake up threads waiting on an address. Either one thread (default) or
 * all threads (if FLAGS_BROADCAST is set) may be woken up. In addition,
 * if the FUTEX_MUTATE bit is set, the address' contents may be set to
 * a specified value (useful for robust futexes).
 */
int futex_wake (int *addr, uint32_t flags, int value);

/*
 * Move waiters sleeping on one futex to another one, optionally waking
 * up a waiter in the process. If FUTEX_BROADCAST is set in flags, moves
 * all waiters; otherwise only one is moved.
 *
 * This function is not implemented for PI futexes.
 */
int futex_requeue (int *dst_addr, int *src_addr,
                   int wake_one, uint32_t flags);

// Clean up all held robust futexes by the calling thread.
void futex_td_exit (struct futex_td *td);

#endif
