/*
 * Copyright (c) 2012-2018 Richard Braun.
 * Copyright (c) 2017 Agustina Arzille.
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
 * Architecture-specific definitions for atomic operations.
 */

#ifndef X86_ATOMIC_H
#define X86_ATOMIC_H

#ifndef KERN_ATOMIC_H
  #error "don't include <machine/atomic.h> directly, use <kern/atomic.h> instead"
#endif

#include <stdbool.h>
#include <stdint.h>

#include <kern/macros.h>

#ifdef __LP64__

// Report that 64-bits operations are supported.
#define ATOMIC_HAVE_64B_OPS

#else

// XXX Clang doesn't provide any __atomic_xxx_8 functions on i386.
#ifndef __clang__

// Report that 64-bits operations are supported.
#define ATOMIC_HAVE_64B_OPS

/*
 * On i386, GCC generates either an FP-stack read/write, or an SSE2
 * store/load to implement these 64-bit atomic operations. Since that's not
 * feasible in the kernel, fall back to cmpxchg8b.
 *
 * XXX Note that, in this case, loading becomes a potentially mutating
 * operation, but it's not expected to be a problem since atomic operations
 * are normally not used on read-only memory.
 *
 * Also note that this assumes the processor is at least an i586.
 */

static inline uint64_t
atomic_load_64 (const void *ptr, int memorder)
{
  uint64_t prev = 0;
  __atomic_compare_exchange_n ((uint64_t *)ptr, &prev, 0, false,
                               memorder, __ATOMIC_RELAXED);
  return (prev);
}

static inline void
atomic_store_64 (void *ptr, void *valp, int memorder)
{
  uint64_t prev = *(uint64_t *)ptr, val = *(uint64_t *)valp;
  bool done;

  do
    done = __atomic_compare_exchange_n ((uint64_t *)ptr, &prev, val, false,
                                        memorder, __ATOMIC_RELAXED);
  while (!done);
}

#endif   // __clang__

#endif   // __LP64__

#endif
