/*
 * Copyright (c) 2017 Richard Braun.
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
 */

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <kern/atomic.h>
#include <kern/init.h>
#include <kern/macros.h>
#include <kern/rtmutex.h>
#include <kern/rtmutex_types.h>
#include <kern/syscnt.h>
#include <kern/thread.h>
#include <kern/turnstile.h>

#ifdef CONFIG_MUTEX_DEBUG

enum
{
  RTMUTEX_SC_WAIT_SUCCESSES,
  RTMUTEX_SC_WAIT_ERRORS,
  RTMUTEX_SC_DOWNGRADES,
  RTMUTEX_SC_ERROR_DOWNGRADES,
  RTMUTEX_SC_CANCELED_DOWNGRADES,
  RTMUTEX_NR_SCS
};

static struct syscnt rtmutex_sc_array[RTMUTEX_NR_SCS];

static void
rtmutex_register_sc (unsigned int index, const char *name)
{
  assert (index < ARRAY_SIZE (rtmutex_sc_array));
  syscnt_register (&rtmutex_sc_array[index], name);
}

static void
rtmutex_setup_debug (void)
{
  rtmutex_register_sc (RTMUTEX_SC_WAIT_SUCCESSES, "rtmutex_wait_successes");
  rtmutex_register_sc (RTMUTEX_SC_WAIT_ERRORS, "rtmutex_wait_errors");
  rtmutex_register_sc (RTMUTEX_SC_DOWNGRADES, "rtmutex_downgrades");
  rtmutex_register_sc (RTMUTEX_SC_ERROR_DOWNGRADES,
                       "rtmutex_error_downgrades");
  rtmutex_register_sc (RTMUTEX_SC_CANCELED_DOWNGRADES,
                       "rtmutex_canceled_downgrades");
}

static void
rtmutex_inc_sc (unsigned int index)
{
  assert (index < ARRAY_SIZE (rtmutex_sc_array));
  syscnt_inc (&rtmutex_sc_array[index]);
}

#else
  #define rtmutex_setup_debug()
  #define rtmutex_inc_sc(x)
#endif

static struct thread*
rtmutex_get_thread (uintptr_t owner)
{
  return ((struct thread *)(owner & RTMUTEX_OWNER_MASK));
}

static void
rtmutex_set_contended (struct rtmutex *rtmutex)
{
  atomic_or (&rtmutex->owner, RTMUTEX_CONTENDED, ATOMIC_RELEASE);
}

static int
rtmutex_lock_slow_common (struct rtmutex *rtmutex, bool timed, uint64_t ticks)
{
  int error = 0;
  uintptr_t self = (uintptr_t)thread_self(), bits = RTMUTEX_CONTENDED;

  struct turnstile *turnstile = turnstile_lend (rtmutex);
  rtmutex_set_contended (rtmutex);

  while (1)
    {
      uintptr_t owner = atomic_cas (&rtmutex->owner, bits,
                                    self | bits, ATOMIC_ACQUIRE);
      assert ((owner & bits) == bits);

      if (owner == bits)
        break;

      struct thread *thread = rtmutex_get_thread (owner);

      if (! timed)
        turnstile_wait (turnstile, "rtmutex", thread);
      else
        {
          error = turnstile_timedwait (turnstile, "rtmutex", thread, ticks);

          if (error)
            break;
        }

      bits |= RTMUTEX_FORCE_WAIT;
    }

  if (error)
    {
      rtmutex_inc_sc (RTMUTEX_SC_WAIT_ERRORS);

      /*
       * Keep in mind more than one thread may have timed out on waiting.
       * These threads aren't considered waiters, making the turnstile
       * potentially empty. The first to reacquire the turnstile clears
       * the contention bits, allowing the owner to unlock through the
       * fast path.
       */
      if (turnstile_empty (turnstile))
        {
          uintptr_t owner = atomic_load (&rtmutex->owner, ATOMIC_RELAXED);

          if (owner & RTMUTEX_CONTENDED)
            {
              rtmutex_inc_sc (RTMUTEX_SC_ERROR_DOWNGRADES);
              owner &= RTMUTEX_OWNER_MASK;
              atomic_store (&rtmutex->owner, owner, ATOMIC_RELAXED);
            }
          else
            rtmutex_inc_sc (RTMUTEX_SC_CANCELED_DOWNGRADES);
        }

      goto out;
    }

  rtmutex_inc_sc (RTMUTEX_SC_WAIT_SUCCESSES);
  turnstile_own (turnstile);

  if (turnstile_empty (turnstile))
    {
      rtmutex_inc_sc (RTMUTEX_SC_DOWNGRADES);
      uintptr_t owner = atomic_swap (&rtmutex->owner, self, ATOMIC_RELAXED);
      assert (owner == (self | bits));
    }

out:
  turnstile_return (turnstile);

  /*
   * A lock owner should never perform priority propagation on itself,
   * because this process is done using its own priority, potentially
   * introducing unbounded priority inversion.
   * Instead, let new waiters do it, using their own priority.
   */

  return (error);
}

void
rtmutex_lock_slow (struct rtmutex *rtmutex)
{
  int error = rtmutex_lock_slow_common (rtmutex, false, 0);
  assert (! error);
}

int
rtmutex_timedlock_slow (struct rtmutex *rtmutex, uint64_t ticks)
{
  return (rtmutex_lock_slow_common (rtmutex, true, ticks));
}

void
rtmutex_unlock_slow (struct rtmutex *rtmutex)
{
  struct turnstile *turnstile;

  for (;;)
    {
      turnstile = turnstile_acquire (rtmutex);

      if (turnstile != NULL)
        break;
      else if (!(rtmutex_unlock_fast (rtmutex) & RTMUTEX_CONTENDED))
        goto out;
    }

  uintptr_t owner = atomic_swap (&rtmutex->owner,
                                 RTMUTEX_FORCE_WAIT | RTMUTEX_CONTENDED,
                                 ATOMIC_RELEASE);
  assert (rtmutex_get_thread (owner) == thread_self ());

  turnstile_disown (turnstile);
  turnstile_signal (turnstile);
  turnstile_release (turnstile);

out:
  thread_propagate_priority ();
}

static int
rtmutex_bootstrap (void)
{
  return (0);
}

INIT_OP_DEFINE (rtmutex_bootstrap,
                INIT_OP_DEP (thread_setup_booter, true));

static int
rtmutex_setup (void)
{
  rtmutex_setup_debug ();
  return (0);
}

#ifdef CONFIG_MUTEX_DEBUG
  #define RTMUTEX_DEBUG_INIT_OPS   INIT_OP_DEP(syscnt_setup, true),
#else
  #define RTMUTEX_DEBUG_INIT_OPS
#endif

INIT_OP_DEFINE (rtmutex_setup,
                INIT_OP_DEP (rtmutex_bootstrap, true),
                RTMUTEX_DEBUG_INIT_OPS
               );
