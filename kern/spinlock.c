/*
 * Copyright (c) 2017-2018 Richard Braun.
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
 * This implementation is based on the paper "Algorithms for Scalable
 * Synchronization on Shared-Memory Multiprocessors" by John M. Mellor-Crummey
 * and Michael L. Scott, which describes MCS locks, among other algorithms.
 *
 * Here are additional issues this module solves that require modifications
 * to the original MCS algorithm :
 *  - There must not be any limit on the number of spin locks a thread may
 *    hold, and spinlocks must not need dynamic memory allocation.
 *  - Unlocking a spin lock must be a non-blocking operation. Without
 *    this requirement, a locking operation may be interrupted in the
 *    middle of a hand-off sequence, preventing the unlock operation
 *    from completing, potentially causing tricky deadlocks.
 *  - Spin lock storage must not exceed 32 bits.
 *
 * In order to solve these issues, the lock owner is never part of the
 * lock queue. This makes it possible to use a qnode only during the lock
 * operation, not after. This means a single qnode per execution context
 * is required even when holding multiple spin locks simultaneously.
 *
 * In addition, instead of making the owner perform a hand-off sequence
 * to unblock the first waiter when unlocking, the latter directly spins
 * on the lock word, and is the one performing the hand-off sequence with
 * the second waiter. As a side effect, this also optimizes spinning for
 * the common case of a single waiter.
 *
 * When a lock is held, the lock bit is set, and when a lock is contended
 * the contended bit is set. When contended, the lock word also contains
 * a compressed reference to the last waiter. That reference is called a
 * QID (for qnode ID). It is structured into two parts :
 *  - the execution context
 *  - the CPU ID
 *
 * The QID is used to uniquely identify a statically allocated qnode.
 *
 * The lock operation must make sure that the lock value is restored
 * to SPINLOCK_LOCKED if there is no more contention, an operation
 * called downgrading.
 */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>

#include <kern/atomic.h>
#include <kern/init.h>
#include <kern/macros.h>
#include <kern/percpu.h>
#include <kern/spinlock.h>
#include <kern/spinlock_types.h>
#include <kern/thread.h>
#include <machine/cpu.h>

#define SPINLOCK_CONTENDED          0x2

#define SPINLOCK_LOCKED_BITS        1
#define SPINLOCK_CONTENDED_BITS     1

#define SPINLOCK_QID_SHIFT   \
  (SPINLOCK_CONTENDED_BITS + SPINLOCK_LOCKED_BITS)

#define SPINLOCK_QID_CTX_BITS       1
#define SPINLOCK_QID_CTX_SHIFT      0
#define SPINLOCK_QID_CTX_MASK       ((1U << SPINLOCK_QID_CTX_BITS) - 1)

#define SPINLOCK_QID_CPU_BITS       29
#define SPINLOCK_QID_CPU_SHIFT   \
  (SPINLOCK_QID_CTX_SHIFT + SPINLOCK_QID_CTX_BITS)

#define SPINLOCK_QID_CPU_MASK       ((1U << SPINLOCK_QID_CPU_BITS) - 1)

#define SPINLOCK_BITS   \
  (SPINLOCK_QID_CPU_BITS + SPINLOCK_QID_CTX_BITS +   \
   SPINLOCK_CONTENDED_BITS + SPINLOCK_LOCKED_BITS)

#if CONFIG_MAX_CPUS > (1U << SPINLOCK_QID_CPU_BITS)
  #error "maximum number of supported processors too large"
#endif

static_assert (SPINLOCK_BITS <= CHAR_BIT * sizeof (uint32_t),
               "spinlock too large");

struct spinlock_qnode
{
  __cacheline_aligned struct spinlock_qnode *next;
  int locked;
};

// TODO NMI support.
enum
{
  SPINLOCK_CTX_THREAD,
  SPINLOCK_CTX_INTR,
  SPINLOCK_NR_CTXS
};

static_assert (SPINLOCK_NR_CTXS <= (SPINLOCK_QID_CTX_MASK + 1),
               "maximum number of contexts too large");

struct spinlock_cpu_data
{
  struct spinlock_qnode qnodes[SPINLOCK_NR_CTXS];
};

static struct spinlock_cpu_data spinlock_cpu_data __percpu;

static struct spinlock_qnode*
spinlock_cpu_data_get_qnode (struct spinlock_cpu_data *cpu_data, uint32_t ctx)
{
  assert (ctx < ARRAY_SIZE (cpu_data->qnodes));
  return (&cpu_data->qnodes[ctx]);
}

static uint32_t
spinlock_qid_build (uint32_t ctx, uint32_t cpu)
{
  assert (ctx <= SPINLOCK_QID_CTX_MASK);
  assert (cpu <= SPINLOCK_QID_CPU_MASK);

  return ((cpu << SPINLOCK_QID_CPU_SHIFT) | (ctx << SPINLOCK_QID_CTX_SHIFT));
}

static uint32_t
spinlock_qid_ctx (uint32_t qid)
{
  return ((qid >> SPINLOCK_QID_CTX_SHIFT) & SPINLOCK_QID_CTX_MASK);
}

static uint32_t
spinlock_qid_cpu (uint32_t qid)
{
  return ((qid >> SPINLOCK_QID_CPU_SHIFT) & SPINLOCK_QID_CPU_MASK);
}

void
spinlock_init (struct spinlock *lock)
{
  lock->value = SPINLOCK_UNLOCKED;

#ifdef SPINLOCK_TRACK_OWNER
  lock->owner = NULL;
#endif
}

static void
spinlock_qnode_init (struct spinlock_qnode *qnode)
{
  qnode->next = NULL;
}

static struct spinlock_qnode*
spinlock_qnode_wait_next (const struct spinlock_qnode *qnode)
{
  while (1)
    {
      _Auto next = atomic_load_acq (&qnode->next);
      if (next)
        return (next);

      atomic_spin_nop ();
    }
}

static void
spinlock_qnode_set_next (struct spinlock_qnode *qnode,
                         struct spinlock_qnode *next)
{
  assert (next);
  atomic_store_rel (&qnode->next, next);
}

static void
spinlock_qnode_set_locked (struct spinlock_qnode *qnode)
{
  qnode->locked = 1;
}

static void
spinlock_qnode_wait_locked (const struct spinlock_qnode *qnode)
{
  while (atomic_load_acq (&qnode->locked))
    atomic_spin_nop ();
}

static void
spinlock_qnode_clear_locked (struct spinlock_qnode *qnode)
{
  atomic_store_rel (&qnode->locked, 0);
}

static void
spinlock_get_local_qnode (struct spinlock_qnode **qnode, uint32_t *qid)
{
  _Auto cpu_data = cpu_local_ptr (spinlock_cpu_data);
  uint32_t ctx = thread_interrupted () ?
    SPINLOCK_CTX_INTR : SPINLOCK_CTX_THREAD;

  *qnode = spinlock_cpu_data_get_qnode (cpu_data, ctx);
  *qid = spinlock_qid_build (ctx, cpu_id ());
}

static uint32_t
spinlock_enqueue (struct spinlock *lock, uint32_t qid)
{
  uint32_t next = (qid << SPINLOCK_QID_SHIFT) | SPINLOCK_CONTENDED;
  while (1)
    {
      uint32_t old_value = atomic_load_rlx (&lock->value);
      uint32_t new_value = next | (old_value & SPINLOCK_LOCKED);
      uint32_t prev = atomic_cas_rel (&lock->value, old_value, new_value);

      if (prev == old_value)
        return (prev);

      atomic_spin_nop ();
    }
}

static struct spinlock_qnode*
spinlock_get_remote_qnode (uint32_t qid)
{
  // This fence synchronizes with queueing.
  atomic_fence_acq ();

  uint32_t ctx = spinlock_qid_ctx (qid),
           cpu = spinlock_qid_cpu (qid);
  _Auto cpu_data = percpu_ptr (spinlock_cpu_data, cpu);
  return (spinlock_cpu_data_get_qnode (cpu_data, ctx));
}

static void
spinlock_set_locked (struct spinlock *lock)
{
  atomic_or_rlx (&lock->value, SPINLOCK_LOCKED);
}

static void
spinlock_wait_locked (const struct spinlock *lock)
{
  while (atomic_load_acq (&lock->value) & SPINLOCK_LOCKED)
    atomic_spin_nop ();
}

static int
spinlock_downgrade (struct spinlock *lock, uint32_t qid)
{
  uint32_t value = (qid << SPINLOCK_QID_SHIFT) | SPINLOCK_CONTENDED,
           prev = atomic_cas_rlx (&lock->value, value, SPINLOCK_LOCKED);

  assert (prev & SPINLOCK_CONTENDED);
  return (prev != value ? EBUSY : 0);
}

void
spinlock_lock_slow (struct spinlock *lock)
{
  uint32_t qid;
  struct spinlock_qnode *qnode;

  spinlock_get_local_qnode (&qnode, &qid);
  spinlock_qnode_init (qnode);

  uint32_t prev = spinlock_enqueue (lock, qid);

  if (prev & SPINLOCK_CONTENDED)
    {
      _Auto prev_qn = spinlock_get_remote_qnode (prev >> SPINLOCK_QID_SHIFT);
      spinlock_qnode_set_locked (qnode);
      spinlock_qnode_set_next (prev_qn, qnode);
      spinlock_qnode_wait_locked (qnode);
    }

  /*
   * If uncontended, the previous lock value could be used to check whether
   * the lock bit was also cleared, but this wait operation also enforces
   * acquire ordering.
   */
  spinlock_wait_locked (lock);

  spinlock_own (lock);
  int error = spinlock_downgrade (lock, qid);

  if (! error)
    return;

  spinlock_set_locked (lock);
  _Auto next_qnode = spinlock_qnode_wait_next (qnode);
  spinlock_qnode_clear_locked (next_qnode);
}

static int __init
spinlock_setup (void)
{
  return (0);
}

INIT_OP_DEFINE (spinlock_setup,
                INIT_OP_DEP (thread_setup_booter, true));
