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
#define ATOMIC_RELAXED   __ATOMIC_RELAXED
#define ATOMIC_CONSUME   __ATOMIC_CONSUME
#define ATOMIC_ACQUIRE   __ATOMIC_ACQUIRE
#define ATOMIC_RELEASE   __ATOMIC_RELEASE
#define ATOMIC_ACQ_REL   __ATOMIC_ACQ_REL
#define ATOMIC_SEQ_CST   __ATOMIC_SEQ_CST

#define __atomic_cas(place, exp, nval, mo)   \
  ({   \
     typeof (*(place)) exp_ = (exp);   \
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
    ({   \
       typeof (val) val_ = (val);   \
       if (sizeof (*(place)) == sizeof (uint64_t))   \
         atomic_store_64 ((place), &val_, (mo));   \
       else   \
         __atomic_store_n ((place), val_, (mo));   \
       (void)0;   \
     })

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

#define atomic_swap(place, val, mo)       atomic_op (place, swap, val, mo)
#define atomic_cas(place, exp, val, mo)   atomic_op (place, cas, exp, val, mo)

#define atomic_cas_bool(place, exp, val, mo)   \
  ({   \
     typeof (*(place)) sexp_ = (exp);   \
     atomic_cas (place, sexp_, val, mo) == sexp_;   \
   })

#define atomic_fence(mo)   __atomic_thread_fence (mo)

#ifndef atomic_spin_nop
  #define atomic_spin_nop()   atomic_fence (ATOMIC_SEQ_CST)
#endif

// Common shortcuts.

#define atomic_load_rlx(place)   atomic_load ((place), ATOMIC_RELAXED)
#define atomic_load_acq(place)   atomic_load ((place), ATOMIC_ACQUIRE)
#define atomic_load_seq(place)   atomic_load ((place), ATOMIC_SEQ_CST)

#define atomic_store_rlx(...)   atomic_store (__VA_ARGS__, ATOMIC_RELAXED)
#define atomic_store_rel(...)   atomic_store (__VA_ARGS__, ATOMIC_RELEASE)
#define atomic_store_seq(...)   atomic_store (__VA_ARGS__, ATOMIC_SEQ_CST)

#define atomic_add_rlx(...)   atomic_add (__VA_ARGS__, ATOMIC_RELAXED)
#define atomic_add_rel(...)   atomic_add (__VA_ARGS__, ATOMIC_RELEASE)

#define atomic_sub_rlx(...)       atomic_sub (__VA_ARGS__, ATOMIC_RELAXED)
#define atomic_sub_rel(...)       atomic_sub (__VA_ARGS__, ATOMIC_RELEASE)
#define atomic_sub_acq_rel(...)   atomic_sub (__VA_ARGS__, ATOMIC_ACQ_REL)

#define atomic_and_rlx(...)   atomic_and (__VA_ARGS__, ATOMIC_RELAXED)
#define atomic_and_rel(...)   atomic_and (__VA_ARGS__, ATOMIC_RELEASE)

#define atomic_or_rlx(...)   atomic_or (__VA_ARGS__, ATOMIC_RELAXED)
#define atomic_or_rel(...)   atomic_or (__VA_ARGS__, ATOMIC_RELEASE)

#define atomic_xor_rlx(...)   atomic_xor (__VA_ARGS__, ATOMIC_RELAXED)
#define atomic_xor_rel(...)   atomic_xor (__VA_ARGS__, ATOMIC_RELEASE)

#define atomic_cas_rlx(...)       atomic_cas (__VA_ARGS__, ATOMIC_RELAXED)
#define atomic_cas_acq(...)       atomic_cas (__VA_ARGS__, ATOMIC_ACQUIRE)
#define atomic_cas_rel(...)       atomic_cas (__VA_ARGS__, ATOMIC_RELEASE)
#define atomic_cas_acq_rel(...)   atomic_cas (__VA_ARGS__, ATOMIC_ACQ_REL)

#define atomic_cas_bool_rlx(...)   \
  atomic_cas_bool (__VA_ARGS__, ATOMIC_RELAXED)

#define atomic_cas_bool_acq(...)   \
  atomic_cas_bool (__VA_ARGS__, ATOMIC_ACQUIRE)

#define atomic_cas_bool_rel(...)   \
  atomic_cas_bool (__VA_ARGS__, ATOMIC_RELEASE)

#define atomic_cas_bool_acq_rel(...)   \
  atomic_cas_bool (__VA_ARGS__, ATOMIC_ACQ_REL)

#define atomic_swap_rlx(...)   atomic_swap (__VA_ARGS__, ATOMIC_RELAXED)
#define atomic_swap_rel(...)   atomic_swap (__VA_ARGS__, ATOMIC_RELEASE)

#define atomic_fence_acq()       atomic_fence (ATOMIC_ACQUIRE)
#define atomic_fence_rel()       atomic_fence (ATOMIC_RELEASE)
#define atomic_fence_acq_rel()   atomic_fence (ATOMIC_ACQ_REL)
#define atomic_fence_seq()       atomic_fence (ATOMIC_SEQ_CST)

/*
 * Try to increment a counter from a non-zero value.
 * Evaluates to true on success.
 */
#define atomic_try_inc(place, mo)   \
  ({   \
     bool done_ = true;   \
     _Auto place_ = (place);   \
     while (1)   \
       {   \
         _Auto tmp_ = atomic_load_rlx (place_);   \
         if (!tmp_)   \
           {   \
             done_ = false;   \
             break;   \
           }   \
         else if (atomic_cas_bool (place_, tmp_, tmp_ + 1, (mo)))   \
           break;   \
         \
         atomic_spin_nop ();   \
       }   \
     done_;   \
   })

#endif
