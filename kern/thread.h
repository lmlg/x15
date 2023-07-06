/*
 * Copyright (c) 2012-2018 Richard Braun.
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
 * The thread module aims at providing an interface suitable to implement
 * POSIX scheduling policies. As such, it provides scheduling classes and
 * policies that closely match the standard ones. The "real-time" policies
 * (FIFO and RR) directly map the first-in first-out (SCHED_FIFO) and
 * round-robin (SCHED_RR) policies, while the "fair-scheduling" policy (FS)
 * can be used for the normal SCHED_OTHER policy. The idle policy is reserved
 * for idling kernel threads.
 *
 * By convention, the name of a kernel thread is built by concatenating the
 * kernel name and the name of the start function, separated with an underscore.
 * Threads that are bound to a processor also include the "/cpu_id" suffix.
 * For example, "x15_thread_balance/1" is the name of the inter-processor
 * balancer thread of the second processor.
 */

#ifndef KERN_THREAD_H
#define KERN_THREAD_H

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdnoreturn.h>

#include <kern/atomic.h>
#include <kern/cpumap.h>
#include <kern/init.h>
#include <kern/cpumap.h>
#include <kern/kernel.h>
#include <kern/kuid.h>
#include <kern/list_types.h>
#include <kern/macros.h>
#include <kern/perfmon_types.h>
#include <kern/rcu_types.h>
#include <kern/spinlock_types.h>
#include <kern/turnstile_types.h>
#include <kern/types.h>
#include <kern/unwind.h>

#include <machine/cpu.h>
#include <machine/tcb.h>

/*
 * The global priority of a thread is meant to be compared against
 * another global priority to determine which thread has higher priority.
 */
struct thread_sched_data
{
  uint8_t sched_policy;
  uint8_t sched_class;
  uint16_t priority;
  uint32_t global_priority;
};

// Thread name buffer size.
#define THREAD_NAME_SIZE   32

// Forward declarations.
struct sleepq;

struct thread_runq;
struct thread_fs_runq;

// Thread flags.
#define THREAD_YIELD      0x1UL   // Must yield the processor ASAP.
#define THREAD_DETACHED   0x2UL   // Resources automatically released on exit.

// Scheduling data for a real-time thread.
struct thread_rt_data
{
  struct list node;
  uint16_t time_slice;
};

// Scheduling data for a fair-scheduling thread.
struct thread_fs_data
{
  struct list group_node;
  struct list runq_node;
  struct thread_fs_runq *fs_runq;
  size_t round;
  uint16_t weight;
  uint16_t work;
};

/*
 * Thread structure.
 *
 * Threads don't have their own lock. Instead, the associated run queue
 * lock is used for synchronization. A number of members are thread-local
 * and require no synchronization. Others must be accessed with atomic
 * instructions.
 *
 * Locking keys :
 * (r) run queue
 * (t) turnstile_td
 * (T) task
 * (j) join_lock
 * (a) atomic
 * (-) thread-local
 * ( ) read-only
 *
 * (*) The runq member is used to determine which run queue lock must be
 * held to serialize access to the relevant members. However, it is only
 * updated while the associated run queue is locked. As a result, atomic
 * reads are only necessary outside critical sections.
 */
struct thread
{
  __cacheline_aligned struct tcb tcb;   // (r)

  struct kuid_head kuid;   // (a)
  unsigned long flags;     // (a)

  // Sleep/wake-up synchronization members.
  struct thread_runq *runq;   // (r,*)
  bool in_runq;               // (r)
  const void *wchan_addr;     // (r)
  const char *wchan_desc;     // (r)
  int wakeup_error;           // (r)
  uint32_t state;             // (a,r)

  // Sleep queue available for lending.
  struct sleepq *priv_sleepq;   // (-)

  // Turnstile available for lending.
  struct turnstile *priv_turnstile;   // (-)
  struct turnstile_td turnstile_td;   // (t)

  // True if priority must be propagated when preemption is reenabled.
  bool propagate_priority;    // (-)

  // Preemption level, preemption is enabled if 0.
  uint16_t preempt_level;   // (-)

  // Pin level, migration is allowed if 0.
  uint16_t pin_level;       // (-)

  // Interrupt level, in thread context if 0.
  uint16_t intr_level;      // (-)

  // Page fault enablement level. Page faults are enabled if 0.
  uint16_t pagefault_level;

  // RCU per-thread data,
  struct rcu_reader rcu_reader;   // (-)

  // Processors on which this thread is allowed to run.
  struct cpumap cpumap;   // (r)

  struct thread_sched_data user_sched_data;   // (r,t)
  struct thread_sched_data real_sched_data;   // (r,t)

  /*
   * True if the real scheduling data are not the user scheduling data.
   *
   * Note that it doesn't provide any information about priority inheritance.
   * A thread may be part of a priority inheritance chain without its
   * priority being boosted.
   */
  bool boosted;   // (r,t)

  // True if the thread is marked to suspend.
  bool suspend;   // (r)

  union
    {
      struct thread_rt_data rt_data;  // (r)
      struct thread_fs_data fs_data;  // (r)
    };

  /*
   * Members related to termination.
   *
   * The termination protocol is made of two steps :
   *  1/ The thread exits, thereby releasing its self reference, and
   *     sets its state to dead before calling the scheduler.
   *  2/ Another thread must either already be joining, or join later.
   *     When the thread reference counter drops to zero, the terminating
   *     flag is set, and the joining thread is awoken, if any. After that,
   *     the join operation polls the state until it sees the target thread
   *     as dead, and then releases its resources.
   */
  struct thread *join_waiter;     // (j)
  struct spinlock join_lock;
  bool terminating;               // (j)

  struct task *task;              // (T)
  struct list task_node;          // (T)
  void *stack;                    // (-)
  char name[THREAD_NAME_SIZE];    // (T)

#ifdef CONFIG_PERFMON
  struct perfmon_td perfmon_td;   // ( )
#endif

  struct unw_fixup_t *fixup;      // (-)
  int64_t cur_rcvid;              // (-)
  struct thread *cur_peer;        // (-)
};

// Thread IPC message (TODO: Move to a specific header).
struct thread_ipc_msg
{
  uint32_t size;
  int op;
  union
    {
      char name[THREAD_NAME_SIZE];
      struct
        {
          void *map;
          uint32_t size;
        } cpumap;
      int id;
    };
};

// Thread IPC operations.
enum
{
  THREAD_IPC_GET_NAME,
  THREAD_IPC_SET_NAME,
  THREAD_IPC_GET_AFFINITY,
  THREAD_IPC_SET_AFFINITY,
  THREAD_IPC_GET_ID,
};

// Thread flags.
#define THREAD_ATTR_DETACHED   0x1

void thread_terminate (struct thread *thread);

// Flag access functions.

static inline void
thread_set_flag (struct thread *thread, unsigned long flag)
{
  atomic_or_rel (&thread->flags, flag);
}

static inline void
thread_clear_flag (struct thread *thread, unsigned long flag)
{
  atomic_and_rel (&thread->flags, ~flag);
}

static inline int
thread_test_flag (struct thread *thread, unsigned long flag)
{
  return ((atomic_load_acq (&thread->flags) & flag) != 0);
}

#define THREAD_KERNEL_PREFIX   KERNEL_NAME "_"

// Thread states.
#define THREAD_RUNNING      0
#define THREAD_SLEEPING     1
#define THREAD_DEAD         2
#define THREAD_SUSPENDED    3

/*
 * Scheduling policies.
 *
 * The idle policy is reserved for the per-CPU idle threads.
 */
#define THREAD_SCHED_POLICY_FIFO    0
#define THREAD_SCHED_POLICY_RR      1
#define THREAD_SCHED_POLICY_FS      2
#define THREAD_SCHED_POLICY_IDLE    3
#define THREAD_NR_SCHED_POLICIES    4

// Real-time priority properties.
#define THREAD_SCHED_RT_PRIO_MIN        0
#define THREAD_SCHED_RT_PRIO_MAX        31

// Fair-scheduling priority properties.
#define THREAD_SCHED_FS_PRIO_MIN        0
#define THREAD_SCHED_FS_PRIO_DEFAULT    20
#define THREAD_SCHED_FS_PRIO_MAX        39

// Thread creation attributes.
struct thread_attr
{
  const char *name;
  size_t flags;
  struct cpumap *cpumap;
  struct task *task;
  uint8_t policy;
  uint16_t priority;
};

/*
 * Initialize thread creation attributes with default values.
 *
 * It is guaranteed that these default values include :
 *  - thread is joinable
 *  - no processor affinity
 *  - task is inherited from parent thread
 *  - policy is fair-scheduling
 *  - priority is fair-scheduling default
 *  - no user stack
 *
 * If the policy is changed, the priority, if applicable, must be updated
 * as well.
 */
static inline void
thread_attr_init (struct thread_attr *attr, const char *name)
{
  attr->name = name;
  attr->flags = 0;
  attr->cpumap = NULL;
  attr->task = NULL;
  attr->policy = THREAD_SCHED_POLICY_FS;
  attr->priority = THREAD_SCHED_FS_PRIO_DEFAULT;
}

static inline void
thread_attr_set_detached (struct thread_attr *attr)
{
  attr->flags |= THREAD_ATTR_DETACHED;
}

static inline void
thread_attr_set_cpumap (struct thread_attr *attr, struct cpumap *cpumap)
{
  attr->cpumap = cpumap;
}

static inline void
thread_attr_set_task (struct thread_attr *attr, struct task *task)
{
  attr->task = task;
}

static inline void
thread_attr_set_policy (struct thread_attr *attr, uint8_t policy)
{
  attr->policy = policy;
}

static inline void
thread_attr_set_priority (struct thread_attr *attr, uint16_t priority)
{
  attr->priority = priority;
}

/*
 * Thread entry point.
 *
 * Loaded TCBs are expected to call this function with interrupts disabled.
 */
void thread_main (void (*fn) (void *), void *arg);

// Initialization of the thread module on APs.
void thread_ap_setup (void);

/*
 * Create a thread.
 *
 * Creation attributes must be passed, but some of them may be NULL, in which
 * case the value is inherited from the caller. The name attribute must not be
 * NULL.
 *
 * If successful, and if the caller passed a non-NULL thread pointer, it is
 * filled with the address of the newly created thread.
 */
int thread_create (struct thread **threadp, const struct thread_attr *attr,
                   void (*fn) (void *), void *arg);

// Terminate the calling thread.
noreturn void thread_exit (void);

// Wait for the given thread to terminate and release its resources.
void thread_join (struct thread *thread);

/*
 * Make the current thread sleep while waiting for an event.
 *
 * The interlock is used to synchronize the thread state with respect to
 * wake-ups, i.e. a wake-up request sent by another thread cannot be missed
 * if that thread is holding the interlock.
 *
 * As a special exception, threads that use preemption as a synchronization
 * mechanism can omit the interlock and pass a NULL pointer instead.
 * In any case, the preemption nesting level must strictly be one when calling
 * this function.
 *
 * The wait channel describes the reason why the thread is sleeping. The
 * address should refer to a relevant synchronization object, normally
 * containing the interlock, but not necessarily.
 *
 * When bounding the duration of the sleep, the caller must pass an absolute
 * time in ticks, and ETIMEDOUT is returned if that time is reached before
 * the thread is awoken.
 *
 * Implies a memory barrier.
 */
void thread_sleep (struct spinlock *interlock, const void *wchan_addr,
                   const char *wchan_desc);
int thread_timedsleep (struct spinlock *interlock, const void *wchan_addr,
                       const char *wchan_desc, uint64_t ticks);

/*
 * Schedule a thread for execution on a processor.
 *
 * If the target thread is NULL, the calling thread, or already in the
 * running state, or in the suspended state, no action is performed and
 * EINVAL is returned.
 *
 * TODO Describe memory ordering with regard to thread_sleep().
 */
int thread_wakeup (struct thread *thread);

/*
 * Suspend a thread.
 *
 * A suspended thread may only be resumed by calling thread_resume().
 *
 * This operation is asynchronous, i.e. the caller must not expect the target
 * thread to be suspended on return.
 *
 * If attempting to suspend core system threads, or threads in the dead state,
 * or if the given thread is NULL, the request is ignored and EINVAL is
 * returned. If the target thread is already suspended, the call turns into
 * a no-op and merely returns success.
 */
int thread_suspend (struct thread *thread);

/*
 * Resume a thread.
 *
 * This call is equivalent to thread_wakeup(), with the exception that
 * it may also wake up suspended threads.
 */
int thread_resume (struct thread *thread);

// Suspend execution of the calling thread.
void thread_delay (uint64_t ticks, bool absolute);

/*
 * Start running threads on the local processor.
 *
 * Interrupts must be disabled when calling this function.
 */
noreturn void thread_run_scheduler (void);

/*
 * Make the calling thread release the processor.
 *
 * This call does nothing if preemption is disabled, or the scheduler
 * determines the caller should continue to run (e.g. it's currently the only
 * runnable thread).
 *
 * Implies a full memory barrier if a context switch occurred.
 */
void thread_yield (void);

// Report a scheduling interrupt from a remote processor.
void thread_schedule_intr (void);

/*
 * Report a periodic event on the current processor.
 *
 * Interrupts and preemption must be disabled when calling this function.
 */
void thread_report_periodic_event (void);

// Set thread scheduling parameters.
void thread_setscheduler (struct thread *thread, uint8_t policy,
                          uint16_t priority);

/*
 * Variant used for priority inheritance.
 *
 * The caller must hold the turnstile thread data lock and no turnstile
 * locks when calling this function.
 */
void thread_pi_setscheduler (struct thread *thread, uint8_t policy,
                             uint16_t priority);

static inline void
thread_ref (struct thread *thread)
{
  size_t nr_refs = atomic_add_rlx (&thread->kuid.nr_refs, 1);
  assert (nr_refs != (size_t)-1);
}

static inline void
thread_unref (struct thread *thread)
{
  size_t nr_refs = atomic_sub_acq_rel (&thread->kuid.nr_refs, 1);
  assert (nr_refs);

  if (nr_refs == 1)
    thread_terminate (thread);
}

static inline const void*
thread_wchan_addr (const struct thread *thread)
{
  return (thread->wchan_addr);
}

static inline const char*
thread_wchan_desc (const struct thread *thread)
{
  return (thread->wchan_desc);
}

// Return a character representation of the state of a thread.
char thread_state_to_chr (uint32_t state);

static inline const struct thread_sched_data*
thread_get_user_sched_data (const struct thread *thread)
{
  return (&thread->user_sched_data);
}

static inline const struct thread_sched_data*
thread_get_real_sched_data (const struct thread *thread)
{
  return (&thread->real_sched_data);
}

/*
 * If the caller requires the scheduling data to be stable, it
 * must lock one of the following objects :
 *  - the containing run queue
 *  - the per-thread turnstile data (turnstile_td)
 *
 * Both are locked when scheduling data are updated.
 */

static inline uint8_t
thread_user_sched_policy (const struct thread *thread)
{
  return (thread_get_user_sched_data(thread)->sched_policy);
}

static inline uint8_t
thread_user_sched_class (const struct thread *thread)
{
  return (thread_get_user_sched_data(thread)->sched_class);
}

static inline uint16_t
thread_user_priority (const struct thread *thread)
{
  return (thread_get_user_sched_data(thread)->priority);
}

static inline uint32_t
thread_user_global_priority (const struct thread *thread)
{
  return (thread_get_user_sched_data(thread)->global_priority);
}

static inline uint8_t
thread_real_sched_policy (const struct thread *thread)
{
  return (thread_get_real_sched_data(thread)->sched_policy);
}

static inline uint8_t
thread_real_sched_class (const struct thread *thread)
{
  return (thread_get_real_sched_data(thread)->sched_class);
}

static inline uint16_t
thread_real_priority (const struct thread *thread)
{
  return (thread_get_real_sched_data(thread)->priority);
}

static inline uint32_t
thread_real_global_priority (const struct thread *thread)
{
  return (thread_get_real_sched_data(thread)->global_priority);
}

// Return a string representation of the scheduling class of a thread.
const char* thread_sched_class_to_str (uint8_t sched_class);

static inline struct tcb*
thread_get_tcb (struct thread *thread)
{
  return (&thread->tcb);
}

static inline struct thread*
thread_from_tcb (struct tcb *tcb)
{
  return (structof (tcb, struct thread, tcb));
}

static inline struct thread*
thread_self (void)
{
  return (thread_from_tcb (tcb_current ()));
}

static inline int
thread_id (const struct thread *thread)
{
  return ((int)thread->kuid.id);
}

/*
 * Main scheduler invocation call.
 *
 * Called on return from interrupt or when reenabling preemption.
 */
void thread_schedule (void);

// Sleep queue lending functions.

static inline struct sleepq*
thread_sleepq_lend (struct thread *self)
{
  struct sleepq *sleepq = self->priv_sleepq;
  assert (sleepq);
  self->priv_sleepq = NULL;
  return (sleepq);
}

static inline void
thread_sleepq_return (struct sleepq *sleepq)
{
  assert (sleepq);
  assert (!thread_self()->priv_sleepq);
  thread_self()->priv_sleepq = sleepq;
}

// Turnstile lending functions.

static inline struct turnstile*
thread_turnstile_lend (void)
{
  struct turnstile *turnstile = thread_self()->priv_turnstile;
  assert (turnstile);
  thread_self()->priv_turnstile = NULL;
  return (turnstile);
}

static inline void
thread_turnstile_return (struct turnstile *turnstile)
{
  assert (turnstile);
  assert (!thread_self()->priv_turnstile);
  thread_self()->priv_turnstile = turnstile;
}

static inline struct turnstile_td*
thread_turnstile_td (struct thread *thread)
{
  return (&thread->turnstile_td);
}

// Priority propagation functions.

static inline bool
thread_priority_propagation_needed (void)
{
  return (thread_self()->propagate_priority);
}

static inline void
thread_set_priority_propagation_needed (void)
{
  thread_self()->propagate_priority = true;
}

void thread_propagate_priority (void);

/*
 * Migration control functions.
 *
 * Functions that change the migration state are implicit compiler barriers.
 */

static inline int
thread_pinned (void)
{
  return (thread_self()->pin_level != 0);
}

static void
thread_pin_level (uint16_t *levelp)
{
  ++*levelp;
  assert (*levelp);
  barrier ();
}

static inline void
thread_pin (void)
{
  thread_pin_level (&thread_self()->pin_level);
}

static inline void
thread_unpin_level (uint16_t *levelp)
{
  barrier ();
  assert (*levelp);
  --*levelp;
}

static inline void
thread_unpin (void)
{
  thread_unpin_level (&thread_self()->pin_level);
}

#define THREAD_PIN_GUARD()   \
  CLEANUP (thread_pin_guard_fini) uint16_t __unused *UNIQ(tpg) =   \
    ({   \
       uint16_t *p_ = &thread_self()->pin_level;   \
       thread_pin_level (p_);   \
       p_;   \
     })

static inline void
thread_pin_guard_fini (void *ptr)
{
  thread_unpin_level (*(uint16_t **)ptr);
}

/*
 * Preemption control functions.
 *
 * Functions that change the preemption state are implicit compiler barriers.
 */

static inline int
thread_preempt_enabled (void)
{
  return (thread_self()->preempt_level == 0);
}

static inline void
thread_preempt_disable (void)
{
  struct thread *thread = thread_self ();
  ++thread->preempt_level;
  assert (thread->preempt_level);
  barrier ();
}

static inline void
thread_preempt_enable_no_resched (void)
{
  barrier ();
  struct thread *thread = thread_self ();
  assert (thread->preempt_level);
  --thread->preempt_level;

  /*
   * Don't perform priority propagation here, because this function is
   * called on return from interrupt, where the transient state may
   * incorrectly trigger it.
   */
}

static inline void
thread_preempt_enable (void)
{
  thread_preempt_enable_no_resched ();

  if (thread_priority_propagation_needed () &&
      thread_preempt_enabled ())
    thread_propagate_priority ();

  thread_schedule ();
}

static inline void
thread_preempt_disable_intr_save (cpu_flags_t *flags)
{
  thread_preempt_disable ();
  cpu_intr_save (flags);
}

static inline void
thread_preempt_enable_intr_restore (cpu_flags_t flags)
{
  cpu_intr_restore (flags);
  thread_preempt_enable ();
}

/*
 * Interrupt level control functions.
 *
 * Functions that change the interrupt level are implicit compiler barriers.
 */

static inline bool
thread_interrupted (void)
{
  return (thread_self()->intr_level != 0);
}

static inline bool
thread_check_intr_context (void)
{
  return (thread_interrupted () && !cpu_intr_enabled () &&
          !thread_preempt_enabled ());
}

static inline void
thread_intr_enter_level (uint16_t *ptr)
{
  if (++*ptr == 1)
    thread_preempt_disable ();

  assert (*ptr);
  barrier ();
}

static inline void
thread_intr_enter (void)
{
  thread_intr_enter_level (&thread_self()->intr_level);
}

static inline void
thread_intr_leave_level (uint16_t *ptr)
{
  barrier ();
  assert (*ptr);

  if (--*ptr == 0)
    thread_preempt_enable_no_resched ();
}

static inline void
thread_intr_leave (void)
{
  thread_intr_leave_level (&thread_self()->intr_level);
}

static inline void
thread_intr_guard_fini (void *ptr)
{
  thread_intr_leave_level (*(uint16_t **)ptr);
}

#define THREAD_INTR_GUARD()   \
  CLEANUP (thread_intr_guard_fini) uint16_t __unused *UNIQ(tig) =   \
    ({   \
       uint16_t *p_ = &thread_self()->intr_level;   \
       thread_intr_enter_level (p_);   \
       p_;   \
     })

// RCU functions.

static inline struct rcu_reader*
thread_rcu_reader (struct thread *thread)
{
  return (&thread->rcu_reader);
}

static inline const char*
thread_name (const struct thread *thread)
{
  return (thread->name);
}

#ifdef CONFIG_PERFMON

static inline struct perfmon_td*
thread_get_perfmon_td (struct thread *thread)
{
  return (&thread->perfmon_td);
}

#endif

// Page fault functions.

static inline void
thread_pagefault_enable (void)
{
  --thread_self()->pagefault_level;
}

static inline void
thread_pagefault_disable (void)
{
  ++thread_self()->pagefault_level;
}

/*
 * Return the last CPU on which the thread has been scheduled.
 *
 * This call isn't synchronized, and the caller may obtain an outdated value.
 */
uint32_t thread_cpu (const struct thread *thread);

/*
 * Return the current state of the given thread.
 *
 * This call isn't synchronized, and the caller may obtain an outdated value.
 */
uint32_t thread_state (const struct thread *thread);

/*
 * Return true if the given thread is running.
 *
 * This call isn't synchronized, and the caller may obtain an outdated value.
 */
bool thread_is_running (const struct thread *thread);

// Get the CPU affinity mask of the specified thread.
int thread_get_affinity (const struct thread *thread, struct cpumap *cpumap);

// Set the CPU affinity mask for the specified thread.
int thread_set_affinity (struct thread *thread, const struct cpumap *cpumap);

// Look up a thread by its KUID.
static inline struct thread*
thread_by_kuid (uint32_t kuid)
{
  return (kuid_find_type (kuid, struct thread, kuid, KUID_THREAD));
}

// Lock a thread's run queue.
struct thread_runq* thread_lock_runq (struct thread *thr, cpu_flags_t *flags);

// Unlock a previously acquired run queue.
void thread_unlock_runq (struct thread_runq *runq, cpu_flags_t flags);

// Make the current thread send-blocked.
int thread_send_block (struct spinlock *lock, void *data);

// Make the current thread receive-blocked.
int thread_recv_block (struct spinlock *lock, void *data);

// Hand off scheduling to a specific thread.
void thread_handoff (struct thread *src, struct thread *dst, void *data,
                     struct thread_sched_data *sched);

// Adopt the scheduling parameters of another thread.
void thread_adopt (struct thread *src, struct thread *dst);

// Test that a thread is either send-blocked or reply-blocked.
bool thread_send_reply_blocked (struct thread *thread);

// Handle an IPC message on a thread capability.
struct cap_iters;
struct ipc_msg_data;

ssize_t thread_handle_msg (struct thread *thread, struct cap_iters *src,
                           struct cap_iters *dst, struct ipc_msg_data *data);

/*
 * This init operation provides :
 *  - a dummy thread context for the BSP, allowing the use of thread_self()
 */
INIT_OP_DECLARE (thread_setup_booter);

/*
 * This init operation provides :
 *  - same as thread_setup_booter
 *  - BSP run queue initialization
 */
INIT_OP_DECLARE (thread_bootstrap);

/*
 * This init operation provides :
 *  - thread creation
 *  - module fully initialized
 */
INIT_OP_DECLARE (thread_setup);

#endif
