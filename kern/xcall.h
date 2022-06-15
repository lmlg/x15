/*
 * Copyright (c) 2014-2018 Richard Braun.
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
 *
 * Cross-processor function calls.
 *
 * This module provides the ability to run functions, called cross-calls,
 * on specific processors.
 */

#ifndef KERN_XCALL_H
#define KERN_XCALL_H

#include <stdint.h>

#include <kern/init.h>
#include <kern/spinlock.h>
#include <kern/work.h>

// Type for cross-call functions.
typedef void (*xcall_fn_t) (void *arg);

// Asynchronous cross-call data structure.
struct xcall_async
{
  struct work work;
  xcall_fn_t fn;
  void *arg;
  uint32_t cpu;
  struct spinlock lock;
  struct thread *waiter;
  bool done;
};

/*
 * Run the given cross-call function on a specific processor.
 *
 * The operation is completely synchronous, returning only when the function
 * has finished running on the target processor. Release-acquire ordering is
 * enforced both before and after the function runs on the target processor,
 * so that side effects produced by the caller are visible to the function,
 * and vice-versa on return.
 *
 * The callback function runs in interrupt context. Interrupts must be enabled
 * when calling this function.
 */
void xcall_call (xcall_fn_t fn, void *arg, uint32_t cpu);

// Initialize an async-xcall.
void xcall_async_init (struct xcall_async *async,
                       xcall_fn_t fn, void *arg, uint32_t cpu);

// Same as xcall_call, only it's performed asynchronously.
void xcall_async_call (struct xcall_async *async);

// Wait for an async xcall to finish.
void xcall_async_wait (struct xcall_async *async);

int xcall_async_timedwait (struct xcall_async *async,
                           uint64_t ticks, bool absolute);

static inline bool
xcall_async_done (const struct xcall_async *async)
{
  return (async->done);
}

/*
 * Handle a cross-call interrupt from a remote processor.
 *
 * Called from interrupt context.
 */
void xcall_intr (void);

/*
 * This init operation provides :
 *  - cross-calls are usable
 *  - module fully initialized
 */
INIT_OP_DECLARE (xcall_setup);

#endif
