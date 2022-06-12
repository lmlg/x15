/*
 * Copyright (c) 2022 Agustina Arzille.
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
 * Type-generic, memory-model-aware atomic operations.
 */

#ifndef KERN_ATOMIC_H
#define KERN_ATOMIC_H   1

#include <assert.h>
#include <stdbool.h>

#include <machine/atomic.h>

// Supported memory orders.
#define ATOMIC_RELAXED  __ATOMIC_RELAXED
#define ATOMIC_CONSUME  __ATOMIC_CONSUME
#define ATOMIC_ACQUIRE  __ATOMIC_ACQUIRE
#define ATOMIC_RELEASE  __ATOMIC_RELEASE
#define ATOMIC_ACQ_REL  __ATOMIC_ACQ_REL
#define ATOMIC_SEQ_CST  __ATOMIC_SEQ_CST

#define __atomic_cas(place, exp, nval, mo)   \
  ({   \
     typeof(*(place)) exp_ = (exp);   \
     __atomic_compare_exchange_n ((place), &exp_, (nval), true,   \
                                  (mo), ATOMIC_RELAXED);   \
     exp_;   \
   })

#if !defined (__LP64__) && defined (ATOMIC_HAVE_64B_OPS)

  #define atomic_load(place, mo)   \
    __builtin_choose_expr (sizeof (*(place)) == sizeof (uint64_t),   \
                           atomic_load_64 ((place), (mo)),   \
                           __atomic_load_n ((place), (mo)))

  #define atomic_store(place, val, mo)   \
    do   \
      {   \
        typeof (val) val_ = (val);   \
        if (sizeof (*(place)) == sizeof (uint64_t))   \
          atomic_write_64 ((place), &val_, (mo));   \
        else   \
          __atomic_store_n ((place), val_, (mo));   \
      }   \
    while (0)

#endif


#define atomic_op(place, op, ...)  __atomic_##op (place, ##__VA_ARGS__)

// Needed since we use different names.
#define __atomic_swap    __atomic_exchange_n
#define __atomic_read    __atomic_load_n
#define __atomic_write   __atomic_store_n

#ifndef atomic_load
  #define atomic_load(place, mo)   atomic_op (place, read, mo)
#endif

#ifndef atomic_store
  #define atomic_store(place, val, mo)   atomic_op (place, write, val, mo)
#endif

#define atomic_add(place, val, mo)   atomic_op (place, fetch_add, val, mo)
#define atomic_sub(place, val, mo)   atomic_op (place, fetch_sub, val, mo)
#define atomic_and(place, val, mo)   atomic_op (place, fetch_and, val, mo)
#define atomic_or(place, val, mo)    atomic_op (place, fetch_or, val, mo)
#define atomic_xor(place, val, mo)   atomic_op (place, fetch_xor, val, mo)

#define atomic_swap(place, val, mo)   atomic_op (place, swap, val, mo)

#define atomic_cas(place, exp, val, mo)   atomic_op (place, cas, exp, val, mo)

#define atomic_cas_bool(place, exp, val, mo)   \
  ({   \
     typeof(*(place)) exp_ = (exp);   \
     atomic_cas (place, exp_, val, mo) == exp_;   \
   })

#define atomic_fence(mo)   __atomic_thread_fence (mo)

// Common shortcuts.

#define atomic_load_rlx(place)       atomic_load ((place), ATOMIC_RELAXED)
#define atomic_load_acq(place)       atomic_load ((place), ATOMIC_ACQUIRE)
#define atomic_load_seq(place)   atomic_load ((place), ATOMIC_SEQ_CST)

#define atomic_store_rlx(place, val)   \
  atomic_store ((place), (val), ATOMIC_RELAXED)

#define atomic_store_rel(place, val)   \
  atomic_store ((place), (val), ATOMIC_RELEASE)

#define atomic_store_seq(place, val)   \
  atomic_store ((place), (val), ATOMIC_SEQ_CST)

#define atomic_add_rlx(place, val)   \
  atomic_add ((place), (val), ATOMIC_RELAXED)

#define atomic_add_rel(place, val)   \
  atomic_add ((place), (val), ATOMIC_RELEASE)

#define atomic_sub_rlx(place, val)   \
  atomic_sub ((place), (val), ATOMIC_RELAXED)

#define atomic_sub_rel(place, val)   \
  atomic_sub ((place), (val), ATOMIC_RELEASE)

#define atomic_and_rlx(place, val)   \
  atomic_and ((place), (val), ATOMIC_RELAXED)

#define atomic_and_rel(place, val)   \
  atomic_and ((place), (val), ATOMIC_RELEASE)

#define atomic_or_rlx(place, val)   \
  atomic_or ((place), (val), ATOMIC_RELAXED)

#define atomic_or_rel(place, val)   \
  atomic_or ((place), (val), ATOMIC_RELEASE)

#define atomic_xor_rlx(place, val)   \
  atomic_xor ((place), (val), ATOMIC_RELAXED)

#define atomic_xor_rel(place, val)   \
  atomic_xor ((place), (val), ATOMIC_RELEASE)

#define atomic_cas_rlx(place, exp, val)   \
  atomic_cas ((place), (exp), (val), ATOMIC_RELAXED)

#define atomic_cas_acq(place, exp, val)   \
  atomic_cas ((place), (exp), (val), ATOMIC_ACQUIRE)

#define atomic_cas_rel(place, exp, val)   \
  atomic_cas ((place), (exp), (val), ATOMIC_RELEASE)

#define atomic_cas_acq_rel(place, exp, val)   \
  atomic_cas ((place), (exp), (val), ATOMIC_ACQ_REL)

#define atomic_cas_bool_rlx(place, exp, val)   \
  atomic_cas_bool ((place), (exp), (val), ATOMIC_RELAXED)

#define atomic_cas_bool_acq(place, exp, val)   \
  atomic_cas_bool ((place), (exp), (val), ATOMIC_ACQUIRE)

#define atomic_cas_bool_rel(place, exp, val)   \
  atomic_cas_bool ((place), (exp), (val), ATOMIC_RELEASE)

#define atomic_swap_rlx(place, val)   \
  atomic_swap ((place), (val), ATOMIC_RELAXED)

#define atomic_swap_rel(place, val)   \
  atomic_swap ((place), (val), ATOMIC_RELEASE)

#define atomic_fence_acq()       atomic_fence (ATOMIC_ACQUIRE)
#define atomic_fence_rel()       atomic_fence (ATOMIC_RELEASE)
#define atomic_fence_acq_rel()   atomic_fence (ATOMIC_ACQ_REL)
#define atomic_fence_seq()       atomic_fence (ATOMIC_SEQ_CST)

#endif
