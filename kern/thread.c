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
 * The scheduling algorithm implemented by this module, named Distributed
 * Group Ratio Round-Robin (DGR3), is based on the following papers :
 *  - "Group Ratio Round-Robin: O(1) Proportional Share Scheduling for
 *    Uniprocessor and Multiprocessor Systems" by Bogdan Caprita, Wong Chun
 *    Chan, Jason Nieh, Clifford Stein and Haoqiang Zheng.
 *  - "Efficient and Scalable Multiprocessor Fair Scheduling Using Distributed
 *    Weighted Round-Robin" by Tong li, Dan Baumberger and Scott Hahn.
 *
 * Note that the Group Ratio Round-Robin (GR3) paper offers a multiprocessor
 * extension, but based on a single global queue, which strongly limits its
 * scalability on systems with many processors. That extension isn't used in
 * this implementation.
 *
 * The basic idea is to use GR3 for processor-local scheduling, and Distributed
 * Weighted Round-Robin (DWRR) for inter-processor load balancing. These
 * algorithms were chosen for several reasons. To begin with, they provide
 * fair scheduling, a very desirable property for a modern scheduler. Next,
 * being based on round-robin, their algorithmic complexity is very low (GR3
 * has O(1) scheduling complexity, and O(g) complexity on thread addition
 * or removal, g being the number of groups, with one group per priority, a
 * low number in practice). Finally, they're very simple to implement, making
 * them easy to adjust and maintain.
 *
 * Both algorithms are actually slightly modified for efficiency. First, this
 * version of GR3 is simplified by mapping exactly one group to one priority,
 * and in turn, one weight. This is possible because priorities are intended
 * to match Unix nice values, and systems commonly provide a constant, small
 * set of nice values. This removes the need for accounting deficit. Next,
 * round tracking is used to improve the handling of dynamic events : work
 * scaling is performed only on thread addition, and not when a thread that
 * was removed is added again during the same round. In addition, since GR3
 * is itself a round-robin algorithm, it already provides the feature required
 * from local scheduling by DWRR, namely round slicing. Consequently, DWRR
 * doesn't sit "on top" of GR3, but is actually merged with it. The result is
 * an algorithm that shares the same data for both local scheduling and load
 * balancing.
 *
 * A few terms are used by both papers with slightly different meanings. Here
 * are the definitions used in this implementation :
 *  - The time unit is the system timer period (1 / tick frequency)
 *  - Work is the amount of execution time units consumed
 *  - Weight is the amount of execution time units allocated
 *  - A round is the shortest period during which all threads in a run queue
 *    consume their allocated time (i.e. their work reaches their weight)
 *
 * TODO Sub-tick accounting.
 *
 *
 * TODO Take into account the underlying CPU topology (and adjust load
 * balancing to access the global highest round less frequently on large
 * processor groups, perhaps by applying the load balancing algorithm in a
 * bottom-up fashion with one highest round per processor group).
 *
 * TODO For now, interactivity can not be experimented. The current strategy
 * is to always add threads in front of their group queue and track rounds
 * so that they don't get more time than they should. A direct consequence
 * is that continually spawning threads at short intervals is likely to cause
 * starvation. This could be fixed by adding newly created threads at the back
 * of their group queue. For now, don't overengineer, and wait until all this
 * can actually be tested.
 *
 * TODO Review weight computation (it may be more appropriate to determine
 * weights in a smoother way than a raw scaling).
 */

#include <assert.h>
#include <errno.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdnoreturn.h>
#include <string.h>

#include <kern/atomic.h>
#include <kern/clock.h>
#include <kern/cpumap.h>
#include <kern/init.h>
#include <kern/kmem.h>
#include <kern/list.h>
#include <kern/macros.h>
#include <kern/panic.h>
#include <kern/percpu.h>
#include <kern/perfmon.h>
#include <kern/rcu.h>
#include <kern/shell.h>
#include <kern/sleepq.h>
#include <kern/spinlock.h>
#include <kern/syscnt.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/timer.h>
#include <kern/turnstile.h>
#include <kern/types.h>
#include <kern/work.h>

#include <machine/cpu.h>
#include <machine/page.h>
#include <machine/pmap.h>
#include <machine/tcb.h>

#include <vm/kmem.h>
#include <vm/map.h>

/*
 * Preemption level of a suspended thread.
 *
 * The expected interrupt, preemption and run queue lock state when
 * dispatching a thread is :
 *  - interrupts disabled
 *  - preemption disabled
 *  - run queue locked
 *
 * Locking the run queue increases the preemption level once more,
 * making its value 2.
 */
#define THREAD_SUSPEND_PREEMPT_LEVEL   2

/*
 * Scheduling classes.
 *
 * Classes are sorted by order of priority (lower indexes first). The same
 * class can apply to several policies.
 *
 * The idle class is reserved for the per-CPU idle threads.
 */
#define THREAD_SCHED_CLASS_RT     0
#define THREAD_SCHED_CLASS_FS     1
#define THREAD_SCHED_CLASS_IDLE   2
#define THREAD_NR_SCHED_CLASSES   3

/*
 * Global priority bases for each scheduling class.
 *
 * Global priorities are only used to determine which of two threads
 * has the higher priority, and should only matter for priority
 * inheritance.
 *
 * In the current configuration, all fair-scheduling threads have the
 * same global priority.
 */
#define THREAD_SCHED_GLOBAL_PRIO_RT     2
#define THREAD_SCHED_GLOBAL_PRIO_FS     1
#define THREAD_SCHED_GLOBAL_PRIO_IDLE   0

// Default time slice for real-time round-robin scheduling.
#define THREAD_DEFAULT_RR_TIME_SLICE   (CLOCK_FREQ / 10)

/*
 * Maximum number of threads which can be pulled from a remote run queue
 * while interrupts are disabled.
 */
#define THREAD_MAX_MIGRATIONS   16

// Delay (in ticks) between two balance attempts when a run queue is idle.
#define THREAD_IDLE_BALANCE_TICKS   (CLOCK_FREQ / 2)

// Run queue properties for real-time threads.
struct thread_rt_runq
{
  uint32_t bitmap;
  struct list threads[THREAD_SCHED_RT_PRIO_MAX + 1];
};

/*
 * Initial value of the highest round.
 *
 * Set to a high value to make sure overflows are correctly handled.
 */
#define THREAD_FS_INITIAL_ROUND   ((unsigned long)-10)

// Round slice base unit for fair-scheduling threads.
#define THREAD_FS_ROUND_SLICE_BASE   (CLOCK_FREQ / 10)

// Group of threads sharing the same weight.
struct thread_fs_group
{
  struct list node;
  struct list threads;
  uint32_t weight;
  uint32_t work;
};

/*
 * Run queue properties for fair-scheduling threads.
 *
 * The current group pointer has a valid address only when the run queue isn't
 * empty.
 */
struct thread_fs_runq
{
  struct thread_fs_group group_array[THREAD_SCHED_FS_PRIO_MAX + 1];
  struct list groups;
  struct list threads;
  struct thread_fs_group *current;
  uint32_t nr_threads;
  uint32_t weight;
  uint32_t work;
};

/*
 * Per processor run queue.
 *
 * Locking multiple run queues is done in the ascending order of their CPU
 * identifier. Interrupts must be disabled whenever locking a run queue, even
 * a remote one, otherwise an interrupt (which invokes the scheduler on its
 * return path) may violate the locking order.
 */
struct thread_runq
{
  __cacheline_aligned struct spinlock lock;
  uint32_t cpu;
  uint32_t nr_threads;
  struct thread *current;

  // Real-time related members.
  struct thread_rt_runq rt_runq;

  /*
   * Fair-scheduling related members.
   *
   * The current round is set when the active run queue becomes non-empty.
   * It's not reset when both run queues become empty. As a result, the
   * current round has a meaningful value only when at least one thread is
   * present, i.e. the global weight isn't zero.
   */
  size_t fs_round;
  uint32_t fs_weight;
  struct thread_fs_runq fs_runqs[2];
  struct thread_fs_runq *fs_runq_active;
  struct thread_fs_runq *fs_runq_expired;

  struct thread *balancer;
  struct thread *idler;

  // Ticks before the next balancing attempt when a run queue is idle.
  uint32_t idle_balance_ticks;

  struct syscnt sc_schedule_intrs;
  struct syscnt sc_boosts;
};

// Operations of a scheduling class.
struct thread_sched_ops
{
  struct thread_runq* (*select_runq) (struct thread *);
  void (*add) (struct thread_runq *, struct thread *);
  void (*remove) (struct thread_runq *, struct thread *);
  void (*put_prev) (struct thread_runq *, struct thread *);
  struct thread* (*get_next) (struct thread_runq *);
  void (*reset_priority) (struct thread *, uint16_t);
  void (*update_priority) (struct thread *, uint16_t);
  uint32_t (*get_global_priority) (uint16_t);
  void (*set_next) (struct thread_runq *, struct thread *);
  void (*tick) (struct thread_runq *, struct thread *);
};

static struct thread_runq thread_runq __percpu;

/*
 * Statically allocated fake threads that provide thread context to processors
 * during bootstrap.
 */
static struct thread thread_booters[CONFIG_MAX_CPUS] __initdata;

static struct kmem_cache thread_cache;

#ifndef CONFIG_THREAD_STACK_GUARD
  static struct kmem_cache thread_stack_cache;
#endif

static const uint8_t thread_policy_table[THREAD_NR_SCHED_POLICIES] =
{
  [THREAD_SCHED_POLICY_FIFO] = THREAD_SCHED_CLASS_RT,
  [THREAD_SCHED_POLICY_RR] = THREAD_SCHED_CLASS_RT,
  [THREAD_SCHED_POLICY_FS] = THREAD_SCHED_CLASS_FS,
  [THREAD_SCHED_POLICY_IDLE] = THREAD_SCHED_CLASS_IDLE,
};

static const struct thread_sched_ops thread_sched_ops[THREAD_NR_SCHED_CLASSES];

// Map of run queues for which a processor is running.
static struct cpumap thread_active_runqs;

/*
 * Map of idle run queues.
 *
 * Access to this map isn't synchronized. It is merely used as a fast hint
 * to find run queues that are likely to be idle.
 */
static struct cpumap thread_idle_runqs;

/*
 * System-wide value of the current highest round.
 *
 * This global variable is accessed without any synchronization. Its value
 * being slightly inaccurate doesn't harm the fairness properties of the
 * scheduling and load balancing algorithms.
 *
 * There can be moderate bouncing on this word so give it its own cache line.
 */
static struct
{
  __cacheline_aligned volatile size_t value;
} thread_fs_highest_round_struct;

#define thread_fs_highest_round   (thread_fs_highest_round_struct.value)

/*
 * Number of processors which have requested the scheduler to run.
 *
 * This value is used to implement a global barrier across the entire
 * system at boot time, so that inter-processor requests may not be
 * lost in case a processor is slower to initialize.
 */
static uint32_t thread_nr_boot_cpus __initdata;

struct thread_zombie
{
  struct work work;
  struct thread *thread;
};

static uint8_t
thread_policy_to_class (uint8_t policy)
{
  assert (policy < ARRAY_SIZE (thread_policy_table));
  return (thread_policy_table[policy]);
}

static void
thread_set_wchan (struct thread *thread, const void *wchan_addr,
                  const char *wchan_desc)
{
  assert (wchan_addr && wchan_desc);
  thread->wchan_addr = wchan_addr;
  thread->wchan_desc = wchan_desc;
}

static void
thread_clear_wchan (struct thread *thread)
{
  thread->wchan_addr = NULL;
  thread->wchan_desc = NULL;
}

static const struct thread_sched_ops*
thread_get_sched_ops (uint8_t sched_class)
{
  assert (sched_class < ARRAY_SIZE (thread_sched_ops));
  return (&thread_sched_ops[sched_class]);
}

static const struct thread_sched_ops*
thread_get_user_sched_ops (const struct thread *thread)
{
  return (thread_get_sched_ops (thread_user_sched_class (thread)));
}

static const struct thread_sched_ops*
thread_get_real_sched_ops (const struct thread *thread)
{
  return (thread_get_sched_ops (thread_real_sched_class (thread)));
}

static void __init
thread_runq_init_rt (struct thread_runq *runq)
{
  runq->rt_runq.bitmap = 0;
  for (size_t i = 0; i < ARRAY_SIZE (runq->rt_runq.threads); i++)
    list_init (&runq->rt_runq.threads[i]);
}

static void __init
thread_fs_group_init (struct thread_fs_group *group)
{
  list_init (&group->threads);
  group->weight = 0;
  group->work = 0;
}

static void __init
thread_fs_runq_init (struct thread_fs_runq *fs_runq)
{
  for (size_t i = 0; i < ARRAY_SIZE (fs_runq->group_array); i++)
    thread_fs_group_init (&fs_runq->group_array[i]);

  list_init (&fs_runq->groups);
  list_init (&fs_runq->threads);
  fs_runq->nr_threads = 0;
  fs_runq->weight = 0;
  fs_runq->work = 0;
}

static void __init
thread_runq_init_fs (struct thread_runq *runq)
{
  runq->fs_weight = 0;
  runq->fs_runq_active = &runq->fs_runqs[0];
  runq->fs_runq_expired = &runq->fs_runqs[1];
  thread_fs_runq_init (runq->fs_runq_active);
  thread_fs_runq_init (runq->fs_runq_expired);
}

static void __init
thread_runq_init (struct thread_runq *runq, uint32_t cpu,
                  struct thread *booter)
{
  char name[SYSCNT_NAME_SIZE];

  spinlock_init (&runq->lock);
  runq->cpu = cpu;
  runq->nr_threads = 0;
  runq->current = booter;
  thread_runq_init_rt (runq);
  thread_runq_init_fs (runq);
  runq->balancer = NULL;
  runq->idler = NULL;
  runq->idle_balance_ticks = (uint32_t)-1;
  snprintf (name, sizeof (name), "thread_schedule_intrs/%u", cpu);
  syscnt_register (&runq->sc_schedule_intrs, name);
  snprintf (name, sizeof (name), "thread_boosts/%u", cpu);
  syscnt_register (&runq->sc_boosts, name);
}

static inline struct thread_runq*
thread_runq_local (void)
{
  assert (!thread_preempt_enabled () || thread_pinned ());
  return (cpu_local_ptr (thread_runq));
}

static inline uint32_t
thread_runq_cpu (struct thread_runq *runq)
{
  return (runq->cpu);
}

static void
thread_runq_add (struct thread_runq *runq, struct thread *thread)
{
  assert (!cpu_intr_enabled ());
  assert (spinlock_locked (&runq->lock));
  assert (!thread->in_runq);

  const _Auto ops = thread_get_real_sched_ops (thread);
  ops->add (runq, thread);

  if (runq->nr_threads == 0)
    cpumap_clear_atomic (&thread_idle_runqs, thread_runq_cpu (runq));

  ++runq->nr_threads;
  if (thread_real_sched_class (thread) <
      thread_real_sched_class (runq->current))
    thread_set_flag (runq->current, THREAD_YIELD);

  atomic_store_rlx (&thread->runq, runq);
  thread->in_runq = true;
}

static void
thread_runq_remove (struct thread_runq *runq, struct thread *thread)
{
  assert (!cpu_intr_enabled ());
  assert (spinlock_locked (&runq->lock));
  assert (thread->in_runq);

  if (--runq->nr_threads == 0)
    cpumap_set_atomic (&thread_idle_runqs, thread_runq_cpu (runq));

  const _Auto ops = thread_get_real_sched_ops (thread);
  ops->remove (runq, thread);
  thread->in_runq = false;
}

static void
thread_runq_put_prev (struct thread_runq *runq, struct thread *thread)
{
  assert (!cpu_intr_enabled ());
  assert (spinlock_locked (&runq->lock));

  const _Auto ops = thread_get_real_sched_ops (thread);
  if (ops->put_prev)
    ops->put_prev (runq, thread);
}

static struct thread*
thread_runq_get_next (struct thread_runq *runq)
{
  assert (!cpu_intr_enabled ());
  assert (spinlock_locked (&runq->lock));

  for (size_t i = 0; i < ARRAY_SIZE (thread_sched_ops); i++)
    {
      struct thread *thread = thread_sched_ops[i].get_next (runq);

      if (thread)
        {
          atomic_store_rlx (&runq->current, thread);
          return (thread);
        }
    }

  // The idle class should never be empty.
  panic ("thread: unable to find next thread");
}

static void
thread_runq_set_next (struct thread_runq *runq, struct thread *thread)
{
  const _Auto ops = thread_get_real_sched_ops (thread);
  if (ops->set_next)
    ops->set_next (runq, thread);

  atomic_store_rlx (&runq->current, thread);
}

static void
thread_runq_wakeup (struct thread_runq *runq, struct thread *thread)
{
  assert (!cpu_intr_enabled ());
  assert (spinlock_locked (&runq->lock));
  assert (thread->state == THREAD_RUNNING);

  thread_runq_add (runq, thread);

  if (runq != thread_runq_local () &&
      thread_test_flag (runq->current, THREAD_YIELD))
    cpu_send_thread_schedule (thread_runq_cpu (runq));
}

static void
thread_runq_wakeup_balancer (struct thread_runq *runq)
{
  if (runq->balancer->state == THREAD_RUNNING)
    return;

  thread_clear_wchan (runq->balancer);
  atomic_store_rlx (&runq->balancer->state, THREAD_RUNNING);
  thread_runq_wakeup (runq, runq->balancer);
}

static void
thread_runq_schedule_load (struct thread *thread)
{
  pmap_load (thread->task->map->pmap);

#ifdef CONFIG_PERFMON
  perfmon_td_load (thread_get_perfmon_td (thread));
#endif
}

static void
thread_runq_schedule_unload (struct thread *thread __unused)
{
#ifdef CONFIG_PERFMON
  perfmon_td_unload (thread_get_perfmon_td (thread));
#endif
}

static struct thread_runq*
thread_runq_schedule (struct thread_runq *runq)
{
  struct thread *prev = thread_self ();

  assert (__builtin_frame_address (0) >= prev->stack &&
          __builtin_frame_address (0) < prev->stack + TCB_STACK_SIZE);
  assert (prev->preempt_level == THREAD_SUSPEND_PREEMPT_LEVEL);
  assert (!cpu_intr_enabled ());
  assert (spinlock_locked (&runq->lock));

  thread_clear_flag (prev, THREAD_YIELD);
  thread_runq_put_prev (runq, prev);

  if (prev->suspend)
    {
      prev->state = THREAD_SUSPENDED;
      prev->suspend = false;
    }

  if (prev->state != THREAD_RUNNING)
    {
      thread_runq_remove (runq, prev);
      if (!runq->nr_threads && prev != runq->balancer)
        thread_runq_wakeup_balancer (runq);
    }

  struct thread *next = thread_runq_get_next (runq);
  assert (next != runq->idler || !runq->nr_threads);
  assert (next->preempt_level == THREAD_SUSPEND_PREEMPT_LEVEL);

  if (likely (prev != next))
    {
      thread_runq_schedule_unload (prev);

      rcu_report_context_switch (thread_rcu_reader (prev));
      spinlock_transfer_owner (&runq->lock, next);

      /*
       * That's where the true context switch occurs. The next thread must
       * unlock the run queue and reenable preemption. Note that unlocking
       * and locking the run queue again is equivalent to a full memory
       * barrier.
       */
      tcb_switch (&prev->tcb, &next->tcb);

      /*
       * The thread is dispatched on a processor once again.
       *
       * Keep in mind the system state may have changed a lot since this
       * function was called. In particular :
       *  - The next thread may have been destroyed, and must not be
       *    referenced any more.
       *  - The current thread may have been migrated to another processor.
       */
      barrier ();
      thread_runq_schedule_load (prev);

      next = NULL;
      runq = thread_runq_local ();
    }
  else
    next = NULL;

  assert (prev->preempt_level == THREAD_SUSPEND_PREEMPT_LEVEL);
  assert (!cpu_intr_enabled ());
  assert (spinlock_locked (&runq->lock));
  return (runq);
}

static void
thread_runq_double_lock (struct thread_runq *a, struct thread_runq *b)
{
  assert (!cpu_intr_enabled ());
  assert (!thread_preempt_enabled ());
  assert (a != b);

  if (a->cpu < b->cpu)
    {
      spinlock_lock (&a->lock);
      spinlock_lock (&b->lock);
    }
  else
    {
      spinlock_lock (&b->lock);
      spinlock_lock (&a->lock);
    }
}

static struct thread_runq*
thread_sched_rt_select_runq (struct thread *thread)
{
  /*
   * Real-time tasks are commonly configured to run on one specific
   * processor only.
   */
  int i = cpumap_find_first (&thread->cpumap);
  assert (i >= 0);
  assert (cpumap_test (&thread_active_runqs, i));

  struct thread_runq *runq = percpu_ptr (thread_runq, i);
  spinlock_lock (&runq->lock);
  return (runq);
}

static void
thread_sched_rt_add (struct thread_runq *runq, struct thread *thread)
{
  struct thread_rt_runq *rt_runq = &runq->rt_runq;
  struct list *threads = &rt_runq->threads[thread_real_priority (thread)];
  list_insert_tail (threads, &thread->rt_data.node);

  if (list_singular (threads))
    rt_runq->bitmap |= (1ULL << thread_real_priority (thread));

  if (thread_real_sched_class (thread) ==
        thread_real_sched_class (runq->current) &&
      thread_real_priority (thread) > thread_real_priority (runq->current))
    thread_set_flag (runq->current, THREAD_YIELD);
}

static void
thread_sched_rt_remove (struct thread_runq *runq, struct thread *thread)
{
  struct thread_rt_runq *rt_runq = &runq->rt_runq;
  struct list *threads = &rt_runq->threads[thread_real_priority (thread)];
  list_remove (&thread->rt_data.node);

  if (list_empty (threads))
    rt_runq->bitmap &= ~ (1ULL << thread_real_priority (thread));
}

static void
thread_sched_rt_put_prev (struct thread_runq *runq, struct thread *thread)
{
  thread_sched_rt_add (runq, thread);
}

static struct thread*
thread_sched_rt_get_next (struct thread_runq *runq)
{
  struct thread_rt_runq *rt_runq = &runq->rt_runq;
  if (!rt_runq->bitmap)
    return (NULL);

  uint32_t priority = THREAD_SCHED_RT_PRIO_MAX -
                      __builtin_clz (rt_runq->bitmap);
  struct list *threads = &rt_runq->threads[priority];
  assert (!list_empty (threads));
  _Auto thread = list_first_entry (threads, struct thread, rt_data.node);
  thread_sched_rt_remove (runq, thread);
  return (thread);
}

static void
thread_sched_rt_reset_priority (struct thread *thread, uint16_t priority)
{
  assert (priority <= THREAD_SCHED_RT_PRIO_MAX);
  thread->rt_data.time_slice = THREAD_DEFAULT_RR_TIME_SLICE;
}

static uint32_t
thread_sched_rt_get_global_priority (uint16_t priority)
{
  return (THREAD_SCHED_GLOBAL_PRIO_RT + priority);
}

static void
thread_sched_rt_set_next (struct thread_runq *runq, struct thread *thread)
{
  thread_sched_rt_remove (runq, thread);
}

static void
thread_sched_rt_tick (struct thread_runq *runq __unused, struct thread *thread)
{
  if (thread_real_sched_policy (thread) != THREAD_SCHED_POLICY_RR ||
      --thread->rt_data.time_slice > 0)
    return;

  thread->rt_data.time_slice = THREAD_DEFAULT_RR_TIME_SLICE;
  thread_set_flag (thread, THREAD_YIELD);
}

static inline uint16_t
thread_sched_fs_prio2weight (uint16_t priority)
{
  return ((priority + 1) * THREAD_FS_ROUND_SLICE_BASE);
}

static struct thread_runq*
thread_sched_fs_select_runq (struct thread *thread)
{
  struct thread_runq *runq;

  cpumap_for_each (&thread_idle_runqs, i)
    {
      if (!cpumap_test (&thread->cpumap, i))
        continue;

      runq = percpu_ptr (thread_runq, i);
      spinlock_lock (&runq->lock);

      // The run queue really is idle, return it.
      if (runq->current == runq->idler)
        return (runq);

      spinlock_unlock (&runq->lock);
    }

  runq = NULL;
  cpumap_for_each (&thread_active_runqs, i)
    {
      if (!cpumap_test (&thread->cpumap, i))
        continue;

      _Auto tmp = percpu_ptr (thread_runq, i);
      spinlock_lock (&tmp->lock);

      if (! runq)
        {
          runq = tmp;
          continue;
        }

      // A run queue may have become idle.
      if (tmp->current == tmp->idler)
        {
          spinlock_unlock (&runq->lock);
          return (tmp);
        }

      /*
       * The run queue isn't idle, but there are no fair-scheduling thread,
       * which means there are real-time threads.
       */
      if (tmp->fs_weight == 0)
        {
          spinlock_unlock (&tmp->lock);
          continue;
        }

      ssize_t delta = (ssize_t)(tmp->fs_round - runq->fs_round);

      // Look for the least loaded of the run queues in the highest round.
      if (delta > 0 ||
          (!delta && tmp->fs_weight < runq->fs_weight))
        {
          spinlock_unlock (&runq->lock);
          runq = tmp;
          continue;
        }

      spinlock_unlock (&tmp->lock);
    }

  assert (runq);
  return (runq);
}

static uint32_t
thread_sched_fs_enqueue_scale (uint32_t work, uint32_t old_weight,
                               uint32_t new_weight)
{
  assert (old_weight);

#ifndef __LP64__
  if (likely (work < 0x10000 && new_weight < 0x10000))
    return ((work * new_weight) / old_weight);
#endif

  return ((uint32_t)(((uint64_t)work * new_weight) / old_weight));
}

static void
thread_sched_fs_enqueue (struct thread_fs_runq *fs_runq, size_t round,
                         struct thread *thread)
{
  assert (!thread->fs_data.fs_runq);
  assert (thread->fs_data.work <= thread->fs_data.weight);

  _Auto group = &fs_runq->group_array[thread_real_priority (thread)];
  uint32_t group_weight = group->weight + thread->fs_data.weight,
           total_weight = fs_runq->weight + thread->fs_data.weight;
  struct list *node = group->weight ?
                      list_prev (&group->node) : list_last (&fs_runq->groups);
  struct list *init_node = node;

  while (!list_end (&fs_runq->groups, node))
    {
      _Auto tmp = list_entry (node, struct thread_fs_group, node);
      if (tmp->weight >= group_weight)
        break;

      node = list_prev (node);
    }

  if (!group->weight)
    list_insert_after (&group->node, node);
  else if (node != init_node)
    {
      list_remove (&group->node);
      list_insert_after (&group->node, node);
    }

  /*
   * XXX Unfairness can occur if the run queue round wraps around and the
   * thread is "lucky" enough to have the same round value. This should be
   * rare and harmless otherwise.
   */
  if (thread->fs_data.round == round)
    {
      fs_runq->work += thread->fs_data.work;
      group->work += thread->fs_data.work;
    }
  else
    {
      uint32_t group_work, thread_work;

      if (!fs_runq->weight)
        thread_work = 0;
      else
        {
          group_work = group->weight == 0 ?
                       thread_sched_fs_enqueue_scale (fs_runq->work,
                                                      fs_runq->weight,
                                                      thread->fs_data.weight) :
                       thread_sched_fs_enqueue_scale (group->work,
                                                      group->weight,
                                                      group_weight);
          thread_work = group_work - group->work;
          fs_runq->work += thread_work;
          group->work = group_work;
        }

      thread->fs_data.round = round;
      thread->fs_data.work = thread_work;
    }

  ++fs_runq->nr_threads;
  fs_runq->weight = total_weight;
  group->weight = group_weight;

  // Insert at the front of the group to improve interactivity.
  list_insert_head (&group->threads, &thread->fs_data.group_node);
  list_insert_tail (&fs_runq->threads, &thread->fs_data.runq_node);
  thread->fs_data.fs_runq = fs_runq;
}

static void
thread_sched_fs_restart (struct thread_runq *runq)
{
  _Auto fs_runq = runq->fs_runq_active;
  struct list *node = list_first (&fs_runq->groups);
  assert (node);
  fs_runq->current = list_entry (node, struct thread_fs_group, node);

  if (thread_real_sched_class (runq->current) == THREAD_SCHED_CLASS_FS)
    thread_set_flag (runq->current, THREAD_YIELD);
}

static void
thread_sched_fs_add (struct thread_runq *runq, struct thread *thread)
{
  if (!runq->fs_weight)
    runq->fs_round = thread_fs_highest_round;

  uint32_t total_weight = runq->fs_weight + thread->fs_data.weight;

  // TODO Limit the maximum number of threads to prevent this situation.
  if (total_weight < runq->fs_weight)
    panic ("thread: weight overflow");

  runq->fs_weight = total_weight;
  thread_sched_fs_enqueue (runq->fs_runq_active, runq->fs_round, thread);
  thread_sched_fs_restart (runq);
}

static void
thread_sched_fs_dequeue (struct thread *thread)
{
  assert (thread->fs_data.fs_runq);

  _Auto fs_runq = thread->fs_data.fs_runq;
  _Auto group = &fs_runq->group_array[thread_real_priority (thread)];

  thread->fs_data.fs_runq = NULL;
  list_remove (&thread->fs_data.runq_node);
  list_remove (&thread->fs_data.group_node);
  fs_runq->work -= thread->fs_data.work;
  group->work -= thread->fs_data.work;
  fs_runq->weight -= thread->fs_data.weight;
  group->weight -= thread->fs_data.weight;
  --fs_runq->nr_threads;

  if (!group->weight)
    list_remove (&group->node);
  else
    {
      struct list *node = list_next (&group->node),
                  *init_node = node;

      while (!list_end (&fs_runq->groups, node))
        {
          _Auto tmp = list_entry (node, struct thread_fs_group, node);
          if (tmp->weight <= group->weight)
            break;

          node = list_next (node);
        }

      if (node != init_node)
        {
          list_remove (&group->node);
          list_insert_before (&group->node, node);
        }
    }
}

static void
thread_sched_fs_remove (struct thread_runq *runq, struct thread *thread)
{
  runq->fs_weight -= thread->fs_data.weight;
  _Auto fs_runq = thread->fs_data.fs_runq;
  thread_sched_fs_dequeue (thread);

  if (fs_runq != runq->fs_runq_active)
    ;
  else if (!fs_runq->nr_threads)
    thread_runq_wakeup_balancer (runq);
  else
    thread_sched_fs_restart (runq);
}

static void
thread_sched_fs_deactivate (struct thread_runq *runq, struct thread *thread)
{
  assert (thread->fs_data.fs_runq == runq->fs_runq_active);
  assert (thread->fs_data.round == runq->fs_round);

  thread_sched_fs_dequeue (thread);
  ++thread->fs_data.round;
  thread->fs_data.work -= thread->fs_data.weight;
  thread_sched_fs_enqueue (runq->fs_runq_expired, runq->fs_round + 1, thread);

  if (!runq->fs_runq_active->nr_threads)
    thread_runq_wakeup_balancer (runq);
}

static void
thread_sched_fs_put_prev (struct thread_runq *runq, struct thread *thread)
{
  _Auto fs_runq = runq->fs_runq_active;
  _Auto group = &fs_runq->group_array[thread_real_priority (thread)];
  list_insert_tail (&group->threads, &thread->fs_data.group_node);

  if (thread->fs_data.work >= thread->fs_data.weight)
    thread_sched_fs_deactivate (runq, thread);
}

static int
thread_sched_fs_ratio_exceeded (struct thread_fs_group *current,
                                struct thread_fs_group *next)
{
#ifndef __LP64__
  if (likely (current->weight < 0x10000 && next->weight < 0x10000))
    {
      uint32_t ia = (current->work + 1) * next->weight,
               ib = (next->work + 1) * current->weight;
      return (ia > ib);
    }
#endif

  uint64_t a = ((uint64_t)current->work + 1) * next->weight,
           b = ((uint64_t)next->work + 1) * current->weight;
  return (a > b);
}

static struct thread*
thread_sched_fs_get_next (struct thread_runq *runq)
{
  _Auto fs_runq = runq->fs_runq_active;
  if (!fs_runq->nr_threads)
    return (NULL);

  _Auto group = fs_runq->current;
  struct list *node = list_next (&group->node);

  if (list_end (&fs_runq->groups, node))
    group = list_entry (list_first (&fs_runq->groups),
                        struct thread_fs_group, node);
  else
    {
      _Auto next = list_entry (node, struct thread_fs_group, node);
      group = thread_sched_fs_ratio_exceeded (group, next) ?
        next : list_entry (list_first (&fs_runq->groups),
                           struct thread_fs_group, node);
    }

  fs_runq->current = group;
  node = list_first (&group->threads);
  _Auto thread = list_entry (node, struct thread, fs_data.group_node);
  list_remove (node);
  return (thread);
}

static void
thread_sched_fs_reset_priority (struct thread *thread, uint16_t priority)
{
  assert (priority <= THREAD_SCHED_FS_PRIO_MAX);
  thread->fs_data.fs_runq = NULL;
  thread->fs_data.round = 0;
  thread->fs_data.weight = thread_sched_fs_prio2weight (priority);
  thread->fs_data.work = 0;
}

static void
thread_sched_fs_update_priority (struct thread *thread, uint16_t priority)
{
  assert (priority <= THREAD_SCHED_FS_PRIO_MAX);
  thread->fs_data.weight = thread_sched_fs_prio2weight (priority);

  if (thread->fs_data.work >= thread->fs_data.weight)
    thread->fs_data.work = thread->fs_data.weight;
}

static uint32_t
thread_sched_fs_get_global_priority (uint16_t priority __unused)
{
  return (THREAD_SCHED_GLOBAL_PRIO_FS);
}

static void
thread_sched_fs_set_next (struct thread_runq *rq __unused, struct thread *thr)
{
  list_remove (&thr->fs_data.group_node);
}

static void
thread_sched_fs_tick (struct thread_runq *runq, struct thread *thread)
{
  _Auto fs_runq = runq->fs_runq_active;
  ++fs_runq->work;
  _Auto group = &fs_runq->group_array[thread_real_priority (thread)];
  ++group->work;
  thread_set_flag (thread, THREAD_YIELD);
  ++thread->fs_data.work;
}

static void
thread_sched_fs_start_next_round (struct thread_runq *runq)
{
  _Auto tmp = runq->fs_runq_expired;
  runq->fs_runq_expired = runq->fs_runq_active;
  runq->fs_runq_active = tmp;

  if (runq->fs_runq_active->nr_threads)
    {
      ++runq->fs_round;
      ssize_t delta = (ssize_t)(runq->fs_round - thread_fs_highest_round);

      if (delta > 0)
        thread_fs_highest_round = runq->fs_round;

      thread_sched_fs_restart (runq);
    }
}

// Check that a remote run queue satisfies the minimum migration requirements.
static int
thread_sched_fs_balance_eligible (struct thread_runq *runq,
                                  size_t highest_round)
{
  if (!runq->fs_weight ||
      (runq->fs_round != highest_round &&
       runq->fs_round != highest_round - 1))
    return (0);

  uint32_t nr_threads = runq->fs_runq_active->nr_threads +
                        runq->fs_runq_expired->nr_threads;

  if (! nr_threads ||
      (nr_threads == 1 &&
       thread_real_sched_class (runq->current) == THREAD_SCHED_CLASS_FS))
    return (0);

  return (1);
}

// Try to find the most suitable run queue from which to pull threads.
static struct thread_runq*
thread_sched_fs_balance_scan (struct thread_runq *runq,
                              size_t highest_round)
{
  struct thread_runq *remote_runq = NULL;

  unsigned long flags;
  thread_preempt_disable_intr_save (&flags);

  cpumap_for_each (&thread_active_runqs, i)
    {
      _Auto tmp = percpu_ptr (thread_runq, i);
      if (tmp == runq)
        continue;

      spinlock_lock (&tmp->lock);

      if (!thread_sched_fs_balance_eligible (tmp, highest_round))
        {
          spinlock_unlock (&tmp->lock);
          continue;
        }
      else if (! remote_runq)
        {
          remote_runq = tmp;
          continue;
        }
      else if (tmp->fs_weight > remote_runq->fs_weight)
        {
          spinlock_unlock (&remote_runq->lock);
          remote_runq = tmp;
          continue;
        }

      spinlock_unlock (&tmp->lock);
    }

  if (remote_runq)
    spinlock_unlock (&remote_runq->lock);

  thread_preempt_enable_intr_restore (flags);
  return (remote_runq);
}

static uint32_t
thread_sched_fs_balance_pull (struct thread_runq *runq,
                              struct thread_runq *remote_runq,
                              struct thread_fs_runq *fs_runq,
                              uint32_t nr_pulls)
{
  int cpu = thread_runq_cpu (runq);
  struct thread *thread, *tmp;

  list_for_each_entry_safe (&fs_runq->threads, thread, tmp,
                            fs_data.runq_node)
    {
      if (thread == remote_runq->current)
        continue;

      /*
       * The pin level is changed without explicit synchronization.
       * However, it can only be changed by its owning thread. As threads
       * currently running aren't considered for migration, the thread had
       * to be preempted and invoke the scheduler. Since balancer threads
       * acquire the run queue lock, there is strong ordering between
       * changing the pin level and setting the current thread of a
       * run queue.
       *
       * TODO Review comment.
       */
      if (thread->pin_level || !cpumap_test (&thread->cpumap, cpu))
        continue;

      /*
       * Make sure at least one thread is pulled if possible. If one or more
       * thread has already been pulled, take weights into account.
       */
      if (nr_pulls &&
          runq->fs_weight + thread->fs_data.weight >
            remote_runq->fs_weight - thread->fs_data.weight)
        break;

      thread_runq_remove (remote_runq, thread);

      // Don't discard the work already accounted for.
      thread->fs_data.round = runq->fs_round;

      thread_runq_add (runq, thread);
      if (++nr_pulls == THREAD_MAX_MIGRATIONS)
        break;
    }

  return (nr_pulls);
}

static uint32_t
thread_sched_fs_balance_migrate (struct thread_runq *runq,
                                 struct thread_runq *remote_runq,
                                 size_t highest_round)
{
  uint32_t nr_pulls = 0;
  if (!thread_sched_fs_balance_eligible (remote_runq, highest_round))
    return (nr_pulls);

  nr_pulls = thread_sched_fs_balance_pull (runq, remote_runq,
                                           remote_runq->fs_runq_active, 0);
  if (nr_pulls == THREAD_MAX_MIGRATIONS)
    return (nr_pulls);

  /*
   * Threads in the expired queue of a processor in round highest are
   * actually in round highest + 1.
   */
  if (remote_runq->fs_round != highest_round)
    nr_pulls = thread_sched_fs_balance_pull (runq, remote_runq,
                                             remote_runq->fs_runq_expired,
                                             nr_pulls);
  return (nr_pulls);
}

/*
 * Inter-processor load balancing for fair-scheduling threads.
 *
 * Preemption must be disabled, and the local run queue must be locked when
 * calling this function. If balancing actually occurs, the lock will be
 * released and preemption enabled when needed.
 */
static void
thread_sched_fs_balance (struct thread_runq *runq, unsigned long *flags)
{
  /*
   * Grab the highest round now and only use the copy so the value is stable
   * during the balancing operation.
   */
  size_t highest_round = thread_fs_highest_round;

  if (runq->fs_round != highest_round &&
      runq->fs_runq_expired->nr_threads)
    goto no_migration;

  spinlock_unlock_intr_restore (&runq->lock, *flags);
  thread_preempt_enable ();

  uint32_t nr_migrations;
  _Auto remote_runq = thread_sched_fs_balance_scan (runq, highest_round);

  if (remote_runq)
    {
      thread_preempt_disable_intr_save (flags);
      thread_runq_double_lock (runq, remote_runq);
      nr_migrations = thread_sched_fs_balance_migrate (runq, remote_runq,
                                                       highest_round);
      spinlock_unlock (&remote_runq->lock);

      if (nr_migrations)
        return;

      spinlock_unlock_intr_restore (&runq->lock, *flags);
      thread_preempt_enable ();
    }

  /*
   * The scan or the migration failed. As a fallback, make another, simpler
   * pass on every run queue, and stop as soon as at least one thread could
   * be successfully pulled.
   */

  cpumap_for_each (&thread_active_runqs, i)
    {
      remote_runq = percpu_ptr (thread_runq, i);
      if (remote_runq == runq)
        continue;

      thread_preempt_disable_intr_save (flags);
      thread_runq_double_lock (runq, remote_runq);
      nr_migrations = thread_sched_fs_balance_migrate (runq, remote_runq,
                                                       highest_round);
      spinlock_unlock (&remote_runq->lock);
      if (nr_migrations != 0)
        return;

      spinlock_unlock_intr_restore (&runq->lock, *flags);
      thread_preempt_enable ();
    }

  thread_preempt_disable ();
  spinlock_lock_intr_save (&runq->lock, flags);

no_migration:

  /*
   * No thread could be migrated. Check the active run queue, as another
   * processor might have added threads while the balancer was running.
   * If the run queue is still empty, switch to the next round. The run
   * queue lock must remain held until the next scheduling decision to
   * prevent a remote balancer thread from stealing active threads.
   */
  if (!runq->fs_runq_active->nr_threads)
    thread_sched_fs_start_next_round (runq);
}

static struct thread_runq*
thread_sched_idle_select_runq (struct thread *thread __unused)
{
  panic ("thread: idler threads cannot be awoken");
}

static noreturn void
thread_sched_idle_panic (void)
{
  panic ("thread: only idle threads are allowed in the idle class");
}

static void
thread_sched_idle_add (struct thread_runq *runq __unused,
                       struct thread *thread __unused)
{
  thread_sched_idle_panic ();
}

#define thread_sched_idle_remove   thread_sched_idle_add

static struct thread*
thread_sched_idle_get_next (struct thread_runq *runq)
{
  return (runq->idler);
}

static uint32_t
thread_sched_idle_get_global_priority (uint16_t priority __unused)
{
  return (THREAD_SCHED_GLOBAL_PRIO_IDLE);
}

static const struct thread_sched_ops thread_sched_ops[THREAD_NR_SCHED_CLASSES] =
{
  [THREAD_SCHED_CLASS_RT] =
    {
      .select_runq = thread_sched_rt_select_runq,
      .add = thread_sched_rt_add,
      .remove = thread_sched_rt_remove,
      .put_prev = thread_sched_rt_put_prev,
      .get_next = thread_sched_rt_get_next,
      .reset_priority = thread_sched_rt_reset_priority,
      .update_priority = NULL,
      .get_global_priority = thread_sched_rt_get_global_priority,
      .set_next = thread_sched_rt_set_next,
      .tick = thread_sched_rt_tick,
    },
  [THREAD_SCHED_CLASS_FS] =
    {
      .select_runq = thread_sched_fs_select_runq,
      .add = thread_sched_fs_add,
      .remove = thread_sched_fs_remove,
      .put_prev = thread_sched_fs_put_prev,
      .get_next = thread_sched_fs_get_next,
      .reset_priority = thread_sched_fs_reset_priority,
      .update_priority = thread_sched_fs_update_priority,
      .get_global_priority = thread_sched_fs_get_global_priority,
      .set_next = thread_sched_fs_set_next,
      .tick = thread_sched_fs_tick,
    },
  [THREAD_SCHED_CLASS_IDLE] =
    {
      .select_runq = thread_sched_idle_select_runq,
      .add = thread_sched_idle_add,
      .remove = thread_sched_idle_remove,
      .put_prev = NULL,
      .get_next = thread_sched_idle_get_next,
      .reset_priority = NULL,
      .update_priority = NULL,
      .get_global_priority = thread_sched_idle_get_global_priority,
      .set_next = NULL,
      .tick = NULL,
    },
};

static void
thread_set_user_sched_policy (struct thread *thread, uint8_t sched_policy)
{
  thread->user_sched_data.sched_policy = sched_policy;
}

static void
thread_set_user_sched_class (struct thread *thread, uint8_t sched_class)
{
  thread->user_sched_data.sched_class = sched_class;
}

static void
thread_set_user_priority (struct thread *thread, uint16_t prio)
{
  const _Auto ops = thread_get_user_sched_ops (thread);
  thread->user_sched_data.priority = prio;
  thread->user_sched_data.global_priority = ops->get_global_priority (prio);
}

static void
thread_update_user_priority (struct thread *thread, uint16_t priority)
{
  thread_set_user_priority (thread, priority);
}

static void
thread_set_real_sched_policy (struct thread *thread, uint8_t sched_policy)
{
  thread->real_sched_data.sched_policy = sched_policy;
}

static void
thread_set_real_sched_class (struct thread *thread, uint8_t sched_class)
{
  thread->real_sched_data.sched_class = sched_class;
}

static void
thread_set_real_priority (struct thread *thread, uint16_t prio)
{
  const _Auto ops = thread_get_real_sched_ops (thread);

  thread->real_sched_data.priority = prio;
  thread->real_sched_data.global_priority = ops->get_global_priority (prio);

  if (ops->reset_priority)
    ops->reset_priority (thread, prio);
}

static void
thread_update_real_priority (struct thread *thread, uint16_t prio)
{
  const _Auto ops = thread_get_real_sched_ops (thread);

  thread->real_sched_data.priority = prio;
  thread->real_sched_data.global_priority = ops->get_global_priority (prio);

  if (ops->update_priority)
    ops->update_priority (thread, prio);
}

static void
thread_reset_real_priority (struct thread *thread)
{
  thread->real_sched_data = thread->user_sched_data;

  _Auto user = &thread->user_sched_data;
  _Auto real = &thread->real_sched_data;
  *real = *user;
  thread->boosted = false;

  const _Auto ops = thread_get_user_sched_ops (thread);
  if (ops->reset_priority)
    ops->reset_priority (thread, real->priority);
}

static void __init
thread_init_booter (uint32_t cpu)
{
  // Initialize only what's needed during bootstrap.
  struct thread *booter = &thread_booters[cpu];
  booter->nr_refs = 0;   // Make sure booters aren't destroyed.
  booter->flags = 0;
  booter->intr_level = 0;
  booter->preempt_level = 1;
  rcu_reader_init (&booter->rcu_reader);
  cpumap_fill (&booter->cpumap);
  thread_set_user_sched_policy (booter, THREAD_SCHED_POLICY_IDLE);
  thread_set_user_sched_class (booter, THREAD_SCHED_CLASS_IDLE);
  thread_set_user_priority (booter, 0);
  thread_reset_real_priority (booter);
  booter->task = task_get_kernel_task ();
  snprintf (booter->name, sizeof (booter->name),
            THREAD_KERNEL_PREFIX "thread_boot/%u", cpu);
}

static int __init
thread_setup_booter (void)
{
  tcb_set_current (&thread_booters[0].tcb);
  thread_init_booter (0);
  return (0);
}

INIT_OP_DEFINE (thread_setup_booter,
                INIT_OP_DEP (tcb_setup, true));

static int __init
thread_bootstrap (void)
{
  cpumap_zero (&thread_active_runqs);
  cpumap_zero (&thread_idle_runqs);

  thread_fs_highest_round = THREAD_FS_INITIAL_ROUND;

  cpumap_set (&thread_active_runqs, 0);
  thread_runq_init (cpu_local_ptr (thread_runq), 0, &thread_booters[0]);
  return (0);
}

INIT_OP_DEFINE (thread_bootstrap,
                INIT_OP_DEP (syscnt_setup, true),
                INIT_OP_DEP (thread_setup_booter, true));

void
thread_main (void (*fn) (void *), void *arg)
{
  assert (!cpu_intr_enabled ());
  assert (!thread_preempt_enabled ());

  struct thread *thread = thread_self ();
  thread_runq_schedule_load (thread);

  spinlock_unlock (&thread_runq_local()->lock);
  cpu_intr_enable ();
  thread_preempt_enable ();

  fn (arg);
  thread_exit ();
}

static int
thread_init (struct thread *thread, void *stack,
             const struct thread_attr *attr,
             void (*fn) (void *), void *arg)
{
  struct thread *caller = thread_self ();
  struct task *task = attr->task ?: caller->task;
  struct cpumap *cpumap = attr->cpumap ?: &caller->cpumap;

  assert (attr->policy < ARRAY_SIZE (thread_policy_table));

  thread->nr_refs = 1;
  thread->flags = 0;
  thread->runq = NULL;
  thread->in_runq = false;
  thread_set_wchan (thread, thread, "init");
  thread->state = THREAD_SLEEPING;
  thread->priv_sleepq = sleepq_create();

  int error;

  if (!thread->priv_sleepq)
    {
      error = ENOMEM;
      goto error_sleepq;
    }

  thread->priv_turnstile = turnstile_create ();
  if (!thread->priv_turnstile)
    {
      error = ENOMEM;
      goto error_turnstile;
    }

  turnstile_td_init (&thread->turnstile_td);
  thread->propagate_priority = false;
  thread->suspend = false;
  thread->preempt_level = THREAD_SUSPEND_PREEMPT_LEVEL;
  thread->pin_level = 0;
  thread->intr_level = 0;
  rcu_reader_init (&thread->rcu_reader);
  cpumap_copy (&thread->cpumap, cpumap);
  thread_set_user_sched_policy (thread, attr->policy);
  thread_set_user_sched_class (thread, thread_policy_to_class (attr->policy));
  thread_set_user_priority (thread, attr->priority);
  thread_reset_real_priority (thread);
  thread->join_waiter = NULL;
  spinlock_init (&thread->join_lock);
  thread->terminating = false;
  thread->task = task;
  thread->stack = stack;
  strlcpy (thread->name, attr->name, sizeof (thread->name));
  thread->fixup = NULL;

#ifdef CONFIG_PERFMON
  perfmon_td_init (thread_get_perfmon_td (thread));
#endif

  if (attr->flags & THREAD_ATTR_DETACHED)
    thread->flags |= THREAD_DETACHED;

  error = tcb_build (&thread->tcb, stack, fn, arg);

  if (error)
    goto error_tcb;

  task_add_thread (task, thread);
  return (0);

error_tcb:
  turnstile_destroy (thread->priv_turnstile);
error_turnstile:
  sleepq_destroy (thread->priv_sleepq);
error_sleepq:
  return (error);
}

static struct thread_runq*
thread_lock_runq (struct thread *thread, unsigned long *flags)
{
  while (1)
    {
      _Auto runq = atomic_load_rlx (&thread->runq);
      spinlock_lock_intr_save (&runq->lock, flags);

      if (likely (runq == atomic_load_rlx (&thread->runq)))
        return (runq);

      spinlock_unlock_intr_restore (&runq->lock, *flags);
    }
}

static void
thread_unlock_runq (struct thread_runq *runq, unsigned long flags)
{
  spinlock_unlock_intr_restore (&runq->lock, flags);
}

#ifdef CONFIG_THREAD_STACK_GUARD

#include <machine/pmap.h>
#include <vm/kmem.h>
#include <vm/page.h>

static void*
thread_alloc_stack (void)
{
  _Auto kernel_pmap = pmap_get_kernel_pmap ();
  size_t stack_size = vm_page_round (TCB_STACK_SIZE);
  void *mem = vm_kmem_alloc ((PAGE_SIZE * 2) + stack_size);

  if (! mem)
    return (NULL);

  uintptr_t va = (uintptr_t)mem;

  /*
   * TODO Until memory protection is implemented, use the pmap system
   * to remove mappings.
   */

  phys_addr_t first_pa, last_pa;
  int error = pmap_kextract (va, &first_pa);
  assert (! error);

  error = pmap_kextract (va + PAGE_SIZE + stack_size, &last_pa);
  assert (! error);

  _Auto first_page = vm_page_lookup (first_pa);
  assert (first_page);

  _Auto last_page = vm_page_lookup (last_pa);
  assert (last_page);

  pmap_remove (kernel_pmap, va, cpumap_all ());
  pmap_remove (kernel_pmap, va + PAGE_SIZE + stack_size, cpumap_all ());
  pmap_update (kernel_pmap);

  return ((char *)va + PAGE_SIZE);
}

static void
thread_free_stack (void *stack)
{
  size_t stack_size = vm_page_round (TCB_STACK_SIZE);
  void *va = (char *)stack - PAGE_SIZE;
  vm_kmem_free (va, (PAGE_SIZE * 2) + stack_size);
}

#else   // CONFIG_THREAD_STACK_GUARD

static void*
thread_alloc_stack (void)
{
  return (kmem_cache_alloc (&thread_stack_cache));
}

static void
thread_free_stack (void *stack)
{
  kmem_cache_free (&thread_stack_cache, stack);
}

#endif

static void
thread_destroy (struct thread *thread)
{
  assert (thread != thread_self ());
  assert (thread->state == THREAD_DEAD);

  // See task_info().
  task_remove_thread (thread->task, thread);

  turnstile_destroy (thread->priv_turnstile);
  sleepq_destroy (thread->priv_sleepq);
  thread_free_stack (thread->stack);
  tcb_cleanup (&thread->tcb);
  kmem_cache_free (&thread_cache, thread);
}

static void
thread_join_common (struct thread *thread)
{
  struct thread *self = thread_self ();
  assert (thread != self);

  spinlock_lock (&thread->join_lock);

  assert (!thread->join_waiter);
  thread->join_waiter = self;

  while (!thread->terminating)
    thread_sleep (&thread->join_lock, thread, "exit");

  spinlock_unlock (&thread->join_lock);

  uint32_t state;
  do
    {
      unsigned long flags;
      _Auto runq = thread_lock_runq (thread, &flags);
      state = thread->state;
      thread_unlock_runq (runq, flags);
    }
  while (state != THREAD_DEAD);

  thread_destroy (thread);
}

void thread_terminate (struct thread *thread)
{
  spinlock_lock (&thread->join_lock);
  thread->terminating = true;
  thread_wakeup (thread->join_waiter);
  spinlock_unlock (&thread->join_lock);
}

static void
thread_balance_idle_tick (struct thread_runq *runq)
{
  assert (runq->idle_balance_ticks != 0);

  /*
   * Interrupts can occur early, at a time the balancer thread hasn't been
   * created yet.
   */
  if (runq->balancer &&
      --runq->idle_balance_ticks == 0)
    thread_runq_wakeup_balancer (runq);
}

static void
thread_balance (void *arg)
{
  struct thread_runq *runq = arg;
  struct thread *self = runq->balancer;
  assert (self == runq->balancer);

  thread_preempt_disable ();

  unsigned long flags;
  spinlock_lock_intr_save (&runq->lock, &flags);

  while (1)
    {
      runq->idle_balance_ticks = THREAD_IDLE_BALANCE_TICKS;
      thread_set_wchan (self, runq, "runq");
      atomic_store_rlx (&self->state, THREAD_SLEEPING);
      runq = thread_runq_schedule (runq);
      assert (runq == arg);

      /*
       * This function may temporarily enable preemption and release the
       * run queue lock, but on return, the lock must remain held until this
       * balancer thread sleeps.
       */
      thread_sched_fs_balance (runq, &flags);
    }
}

static void __init
thread_setup_balancer (struct thread_runq *runq)
{
  struct cpumap *cpumap;
  if (cpumap_create (&cpumap) != 0)
    panic ("thread: unable to create balancer thread CPU map");

  cpumap_zero (cpumap);
  cpumap_set (cpumap, thread_runq_cpu (runq));

  char name[THREAD_NAME_SIZE];
  snprintf (name, sizeof (name), THREAD_KERNEL_PREFIX "thread_balance/%u",
            thread_runq_cpu (runq));

  struct thread_attr attr;
  thread_attr_init (&attr, name);
  thread_attr_set_cpumap (&attr, cpumap);
  thread_attr_set_policy (&attr, THREAD_SCHED_POLICY_FIFO);
  thread_attr_set_priority (&attr, THREAD_SCHED_RT_PRIO_MIN);

  struct thread *balancer;
  int error = thread_create (&balancer, &attr, thread_balance, runq);
  cpumap_destroy (cpumap);

  if (error)
    panic ("thread: unable to create balancer thread");

  runq->balancer = balancer;
}

static void
thread_idle (void *arg __unused)
{
  struct thread *self = thread_self ();
  while (1)
    {
      thread_preempt_disable ();
      while (1)
        {
          cpu_intr_disable ();

          if (thread_test_flag (self, THREAD_YIELD))
            {
              cpu_intr_enable ();
              break;
            }

          cpu_idle ();
        }

      thread_preempt_enable ();
    }
}

static void __init
thread_setup_idler (struct thread_runq *runq)
{
  struct cpumap *cpumap;
  if (cpumap_create (&cpumap) != 0)
    panic ("thread: unable to allocate idler thread CPU map");

  cpumap_zero (cpumap);
  cpumap_set (cpumap, thread_runq_cpu (runq));
  struct thread *idler = kmem_cache_alloc (&thread_cache);

  if (! idler)
    panic ("thread: unable to allocate idler thread");

  void *stack = thread_alloc_stack ();
  if (! stack)
    panic ("thread: unable to allocate idler thread stack");

  char name[THREAD_NAME_SIZE];
  snprintf (name, sizeof (name), THREAD_KERNEL_PREFIX "thread_idle/%u",
            thread_runq_cpu (runq));

  struct thread_attr attr;
  thread_attr_init (&attr, name);
  thread_attr_set_cpumap (&attr, cpumap);
  thread_attr_set_policy (&attr, THREAD_SCHED_POLICY_IDLE);
  if (thread_init (idler, stack, &attr, thread_idle, NULL) != 0)
    panic ("thread: unable to initialize idler thread");

  cpumap_destroy (cpumap);

  // An idler thread needs special tuning.
  thread_clear_wchan (idler);
  idler->state = THREAD_RUNNING;
  idler->runq = runq;
  runq->idler = idler;
}

static void __init
thread_setup_runq (struct thread_runq *runq)
{
  thread_setup_balancer (runq);
  thread_setup_idler (runq);
}

#ifdef CONFIG_SHELL

/*
 * This function is meant for debugging only. As a result, it uses a weak
 * locking policy which allows tracing threads which state may mutate during
 * tracing.
 */
static void
thread_shell_trace (struct shell *shell, int argc, char **argv)
{
  if (argc != 3)
    {
      stream_puts (shell->stream, "usage: thread_trace task thread\n");
      return;
    }

  const char *task_name = argv[1], *thread_name = argv[2];
  struct task *task = task_lookup (task_name);

  if (task == NULL)
    {
      fmt_xprintf (shell->stream, "thread_trace: task not found: %s\n",
                   task_name);
      return;
    }

  struct thread *thread = task_lookup_thread (task, thread_name);
  task_unref (task);

  if (! thread)
    {
      fmt_xprintf (shell->stream, "thread_trace: thread not found: %s\n",
                   thread_name);
      return;
    }

  unsigned long flags;
  _Auto runq = thread_lock_runq (thread, &flags);

  if (thread == runq->current)
    stream_puts (shell->stream, "thread_trace: thread is running\n");
  else
    tcb_trace (&thread->tcb);

  thread_unlock_runq (runq, flags);
  thread_unref (thread);
}

static struct shell_cmd thread_shell_cmds[] =
{
  SHELL_CMD_INITIALIZER ("thread_trace", thread_shell_trace,
                         "thread_trace <task_name> <thread_name>",
                         "display the stack trace of a given thread"),
};

static int __init
thread_setup_shell (void)
{
  SHELL_REGISTER_CMDS (thread_shell_cmds, shell_get_main_cmd_set ());
  return (0);
}

INIT_OP_DEFINE (thread_setup_shell,
                INIT_OP_DEP (printf_setup, true),
                INIT_OP_DEP (shell_setup, true),
                INIT_OP_DEP (task_setup, true),
                INIT_OP_DEP (thread_setup, true));

#endif

static void __init
thread_setup_common (uint32_t cpu)
{
  assert (cpu);
  cpumap_set (&thread_active_runqs, cpu);
  thread_init_booter (cpu);
  thread_runq_init (percpu_ptr (thread_runq, cpu), cpu, &thread_booters[cpu]);
}

static int __init
thread_setup (void)
{
  for (uint32_t cpu = 1; cpu < cpu_count (); cpu++)
    thread_setup_common (cpu);

  kmem_cache_init (&thread_cache, "thread", sizeof (struct thread),
                   CPU_L1_SIZE, NULL, 0);
#ifndef CONFIG_THREAD_STACK_GUARD
  kmem_cache_init (&thread_stack_cache, "thread_stack", TCB_STACK_SIZE,
                   CPU_DATA_ALIGN, NULL, 0);
#endif

  cpumap_for_each (&thread_active_runqs, cpu)
    thread_setup_runq (percpu_ptr (thread_runq, cpu));

  return (0);
}

#ifdef CONFIG_THREAD_STACK_GUARD
  #define THREAD_STACK_GUARD_INIT_OP_DEPS   \
    INIT_OP_DEP (vm_kmem_setup, true),    \
    INIT_OP_DEP (vm_map_setup, true),     \
    INIT_OP_DEP (vm_page_setup, true),
#else
  #define THREAD_STACK_GUARD_INIT_OP_DEPS
#endif

#ifdef CONFIG_PERFMON
  #define THREAD_PERFMON_INIT_OP_DEPS   INIT_OP_DEP (perfmon_bootstrap, true),
#else
  #define THREAD_PERFMON_INIT_OP_DEPS
#endif

INIT_OP_DEFINE (thread_setup,
                INIT_OP_DEP (cpumap_setup, true),
                INIT_OP_DEP (kmem_setup, true),
                INIT_OP_DEP (pmap_setup, true),
                INIT_OP_DEP (sleepq_setup, true),
                INIT_OP_DEP (task_setup, true),
                INIT_OP_DEP (thread_bootstrap, true),
                INIT_OP_DEP (turnstile_setup, true),
                THREAD_STACK_GUARD_INIT_OP_DEPS
                THREAD_PERFMON_INIT_OP_DEPS);

void __init
thread_ap_setup (void)
{
  tcb_set_current (&thread_booters[cpu_id ()].tcb);
}

int
thread_create (struct thread **threadp, const struct thread_attr *attr,
               void (*fn) (void *), void *arg)

{
  int error;
  if (attr->cpumap)
    {
      error = cpumap_check (attr->cpumap);
      if (error)
        return (error);
    }

  struct thread *thread = kmem_cache_alloc (&thread_cache);
  if (! thread)
    {
      error = ENOMEM;
      goto error_thread;
    }

  void *stack = thread_alloc_stack ();
  if (! stack)
    {
      error = ENOMEM;
      goto error_stack;
    }

  error = thread_init (thread, stack, attr, fn, arg);

  if (error)
    goto error_init;

  /*
   * The new thread address must be written before the thread is started
   * in case it's passed to it.
   */
  if (threadp)
    *threadp = thread;

  thread_wakeup (thread);
  return (0);

error_init:
  thread_free_stack (stack);
error_stack:
  kmem_cache_free (&thread_cache, thread);
error_thread:
  return (error);
}

static void
thread_reap (struct work *work)
{
  _Auto zombie = structof (work, struct thread_zombie, work);
  thread_join_common (zombie->thread);
}

void
thread_exit (void)
{
  struct thread_zombie zombie;
  struct thread *thread = thread_self ();

  if (thread_test_flag (thread, THREAD_DETACHED))
    {
      zombie.thread = thread;

      work_init (&zombie.work, thread_reap);
      work_schedule (&zombie.work, 0);
    }

  /*
   * Disable preemption before dropping the reference, as this may
   * trigger the active state poll of the join operation. Doing so
   * keeps the duration of that active wait minimum.
   */
  thread_preempt_disable ();
  thread_unref (thread);

  _Auto runq = thread_runq_local ();

  unsigned long flags;
  spinlock_lock_intr_save (&runq->lock, &flags);
  atomic_store_rlx (&thread->state, THREAD_DEAD);
  thread_runq_schedule (runq);

  panic ("thread: dead thread walking");
}

void
thread_join (struct thread *thread)
{
  assert (!thread_test_flag (thread, THREAD_DETACHED));
  thread_join_common (thread);
}

static int
thread_wakeup_common (struct thread *thread, int error, bool resume)
{
  if (!thread || thread == thread_self ())
    return (EINVAL);

  /*
   * There is at most one reference on threads that were never dispatched,
   * in which case there is no need to lock anything.
   */

  struct thread_runq *runq;
  unsigned long flags;

  if (!thread->runq)
    {
      assert (thread->state != THREAD_RUNNING);
      thread_clear_wchan (thread);
      thread->state = THREAD_RUNNING;
    }
  else
    {
      runq = thread_lock_runq (thread, &flags);

      if (thread->state == THREAD_RUNNING ||
          (thread->state == THREAD_SUSPENDED && !resume))
        {
          thread_unlock_runq (runq, flags);
          return (EINVAL);
        }

      thread_clear_wchan (thread);
      atomic_store_rlx (&thread->state, THREAD_RUNNING);
      thread_unlock_runq (runq, flags);
    }

  thread_preempt_disable_intr_save (&flags);

  if (!thread->pin_level)
    runq = thread_get_real_sched_ops(thread)->select_runq (thread);
  else
    {
      /*
       * This access doesn't need to be atomic, as the current thread is
       * the only one which may update the member.
       */
      runq = thread->runq;
      spinlock_lock (&runq->lock);
    }

  thread->wakeup_error = error;
  thread_runq_wakeup (runq, thread);
  spinlock_unlock (&runq->lock);
  thread_preempt_enable_intr_restore (flags);

  return (0);
}

int
thread_wakeup (struct thread *thread)
{
  return (thread_wakeup_common (thread, 0, false));
}

struct thread_timeout_waiter
{
  struct thread *thread;
  struct timer timer;
};

static void
thread_timeout (struct timer *timer)
{
  _Auto waiter = structof (timer, struct thread_timeout_waiter, timer);
  thread_wakeup_common (waiter->thread, ETIMEDOUT, false);
}

static int
thread_sleep_common (struct spinlock *interlock, const void *wchan_addr,
                     const char *wchan_desc, bool timed, uint64_t ticks)
{
  struct thread *thread = thread_self ();
  struct thread_timeout_waiter waiter;

  if (timed)
    {
      waiter.thread = thread;
      timer_init (&waiter.timer, thread_timeout, TIMER_INTR);
      timer_schedule (&waiter.timer, ticks);
    }

  _Auto runq = thread_runq_local ();

  unsigned long flags;
  spinlock_lock_intr_save (&runq->lock, &flags);

  if (interlock)
    {
      thread_preempt_disable ();
      spinlock_unlock (interlock);
    }

  thread_set_wchan (thread, wchan_addr, wchan_desc);
  atomic_store_rlx (&thread->state, THREAD_SLEEPING);

  runq = thread_runq_schedule (runq);
  assert (thread->state == THREAD_RUNNING);

  spinlock_unlock_intr_restore (&runq->lock, flags);

  if (timed)
    timer_cancel (&waiter.timer);

  if (interlock)
    {
      spinlock_lock (interlock);
      thread_preempt_enable_no_resched ();
    }

  return (thread->wakeup_error);
}

void
thread_sleep (struct spinlock *lock, const void *wchan_addr,
              const char *wchan_desc)
{
  int error = thread_sleep_common (lock, wchan_addr, wchan_desc, false, 0);
  assert (! error);
}

int
thread_timedsleep (struct spinlock *lock, const void *wchan_addr,
                   const char *wchan_desc, uint64_t ticks)
{
  return (thread_sleep_common (lock, wchan_addr, wchan_desc, true, ticks));
}

int
thread_suspend (struct thread *thread)
{
  if (! thread)
    return (EINVAL);

  thread_preempt_disable ();
  unsigned long flags;
  _Auto runq = thread_lock_runq (thread, &flags);

  int error;

  if (thread == runq->idler ||
      thread == runq->balancer ||
      thread->state == THREAD_DEAD)
    error = EINVAL;
  else if (thread->state == THREAD_SUSPENDED || thread->suspend)
    error = 0;
  else if (thread->state == THREAD_SLEEPING)
    {
      thread->state = THREAD_SUSPENDED;
      error = 0;
    }
  else
    {
      assert (thread->state == THREAD_RUNNING);

      if (thread != runq->current)
        {
          thread->state = THREAD_SUSPENDED;
          thread_runq_remove (runq, thread);
        }
      else
        {
          thread->suspend = true;

          if (runq == thread_runq_local ())
            runq = thread_runq_schedule (runq);
          else
            {
              thread_set_flag (thread, THREAD_YIELD);
              cpu_send_thread_schedule (thread_runq_cpu (runq));
            }
        }

      error = 0;
    }

  thread_unlock_runq (runq, flags);
  thread_preempt_enable ();
  return (error);
}

int
thread_resume (struct thread *thread)
{
  return (thread_wakeup_common (thread, 0, true));
}

void
thread_delay (uint64_t ticks, bool absolute)
{
  thread_preempt_disable ();

  if (! absolute)
    // Add a tick to avoid quantization errors.
    ticks += clock_get_time () + 1;

  thread_timedsleep (NULL, thread_self (), "delay", ticks);
  thread_preempt_enable ();
}

static void __init
thread_boot_barrier_wait (void)
{
  assert (!cpu_intr_enabled ());
  atomic_add_rlx (&thread_nr_boot_cpus, 1);

  while (atomic_load_seq (&thread_nr_boot_cpus) != cpu_count ())
    cpu_pause ();
}

void __init
thread_run_scheduler (void)
{
  assert (!cpu_intr_enabled ());
  thread_boot_barrier_wait ();

  _Auto runq = thread_runq_local ();
  struct thread *thread = thread_self ();
  assert (thread == runq->current);
  assert (thread->preempt_level == THREAD_SUSPEND_PREEMPT_LEVEL - 1);

  spinlock_lock (&runq->lock);
  thread = thread_runq_get_next (thread_runq_local ());
  spinlock_transfer_owner (&runq->lock, thread);

  tcb_load (&thread->tcb);
}

void
thread_yield (void)
{
  struct thread *thread = thread_self ();

  if (!thread_preempt_enabled ())
    return;

  do
    {
      thread_preempt_disable ();
      _Auto runq = thread_runq_local ();

      unsigned long flags;
      spinlock_lock_intr_save (&runq->lock, &flags);
      runq = thread_runq_schedule (runq);
      spinlock_unlock_intr_restore (&runq->lock, flags);
      thread_preempt_enable_no_resched ();
    }
  while (thread_test_flag (thread, THREAD_YIELD));
}

void
thread_schedule (void)
{
  if (unlikely (thread_test_flag (thread_self (), THREAD_YIELD)))
    thread_yield ();
}

void
thread_schedule_intr (void)
{
  assert (thread_check_intr_context ());
  syscnt_inc (&thread_runq_local()->sc_schedule_intrs);
}

void
thread_report_periodic_event (void)
{
  assert (thread_check_intr_context ());

  _Auto runq = thread_runq_local ();
  struct thread *thread = thread_self ();

  spinlock_lock (&runq->lock);
  if (!runq->nr_threads)
    thread_balance_idle_tick (runq);

  const _Auto ops = thread_get_real_sched_ops (thread);
  if (ops->tick)
    ops->tick (runq, thread);

  spinlock_unlock (&runq->lock);
}

char
thread_state_to_chr (uint32_t state)
{
  switch (state)
    {
      case THREAD_RUNNING:
        return ('R');
      case THREAD_SLEEPING:
        return ('S');
      case THREAD_DEAD:
        return ('Z');
      case THREAD_SUSPENDED:
        return ('T');
      default:
        panic ("thread: unknown state");
    }
}

const char*
thread_sched_class_to_str (uint8_t sched_class)
{
  switch (sched_class)
    {
      case THREAD_SCHED_CLASS_RT:
        return ("rt");
      case THREAD_SCHED_CLASS_FS:
        return ("fs");
      case THREAD_SCHED_CLASS_IDLE:
        return ("idle");
      default:
        panic ("thread: unknown scheduling class");
    }
}

void
thread_setscheduler (struct thread *thread, uint8_t policy,
                     uint16_t priority)
{
  _Auto td = thread_turnstile_td (thread);
  turnstile_td_lock (td);

  unsigned long flags;
  _Auto runq = thread_lock_runq (thread, &flags);

  if (thread_user_sched_policy (thread) == policy &&
      thread_user_priority (thread) == priority)
    goto out;

  bool current, requeue = thread->in_runq;

  if (! requeue)
    current = false;
  else
    {
      if (thread != runq->current)
        current = false;
      else
        {
          thread_runq_put_prev (runq, thread);
          current = true;
        }

      thread_runq_remove (runq, thread);
    }

  bool update;
  if (thread_user_sched_policy (thread) == policy)
    {
      thread_update_user_priority (thread, priority);
      update = true;
    }
  else
    {
      thread_set_user_sched_policy (thread, policy);
      thread_set_user_sched_class (thread, thread_policy_to_class (policy));
      thread_set_user_priority (thread, priority);
      update = false;
    }

  if (thread->boosted)
    {
      if (thread_user_global_priority (thread) >=
          thread_real_global_priority (thread))
        thread_reset_real_priority (thread);
    }
  else if (update)
    thread_update_real_priority (thread, priority);
  else
    {
      thread_set_real_sched_policy (thread, policy);
      thread_set_real_sched_class (thread, thread_policy_to_class (policy));
      thread_set_real_priority (thread, priority);
    }

  if (requeue)
    {
      thread_runq_add (runq, thread);
      if (current)
        thread_runq_set_next (runq, thread);
    }

out:
  thread_unlock_runq (runq, flags);
  turnstile_td_unlock (td);
  turnstile_td_propagate_priority (td);
}

void
thread_pi_setscheduler (struct thread *thread, uint8_t policy,
                        uint16_t priority)
{
  _Auto td = thread_turnstile_td (thread);
  assert (turnstile_td_locked (td));

  const _Auto ops = thread_get_sched_ops (thread_policy_to_class (policy));
  uint32_t global_priority = ops->get_global_priority (priority);

  unsigned long flags;
  _Auto runq = thread_lock_runq (thread, &flags);

  if (thread_real_sched_policy (thread) == policy &&
      thread_real_priority (thread) == priority)
    goto out;

  syscnt_inc (&runq->sc_boosts);
  bool current, requeue = thread->in_runq;

  if (! requeue)
    current = false;
  else
    {
      if (thread != runq->current)
        current = false;
      else
        {
          thread_runq_put_prev (runq, thread);
          current = true;
        }

      thread_runq_remove (runq, thread);
    }

  if (global_priority <= thread_user_global_priority (thread))
    thread_reset_real_priority (thread);
  else
    {
      if (thread_real_sched_policy (thread) == policy)
        thread_update_real_priority (thread, priority);
      else
        {
          thread_set_real_sched_policy (thread, policy);
          thread_set_real_sched_class (thread,
                                       thread_policy_to_class (policy));
          thread_set_real_priority (thread, priority);
        }

      thread->boosted = true;
    }

  if (requeue)
    {
      thread_runq_add (runq, thread);
      if (current)
        thread_runq_set_next (runq, thread);
    }

out:
  thread_unlock_runq (runq, flags);
}

void
thread_propagate_priority (void)
{
  /*
   * Although it's possible to propagate priority with preemption
   * disabled, the operation can be too expensive to allow it.
   */
  if (!thread_preempt_enabled ())
    {
      thread_set_priority_propagation_needed ();
      return;
    }

  struct thread *thread = thread_self();

  // Clear before propagation to avoid infinite recursion.
  thread->propagate_priority = false;
  turnstile_td_propagate_priority (thread_turnstile_td (thread));
}

uint32_t
thread_cpu (const struct thread *thread)
{
  const _Auto runq = atomic_load_rlx (&thread->runq);
  return (runq->cpu);
}

uint32_t
thread_state (const struct thread *thread)
{
  return (atomic_load_rlx (&thread->state));
}

bool
thread_is_running (const struct thread *thread)
{
  const _Auto runq = atomic_load_rlx (&thread->runq);
  return (runq && atomic_load_rlx (&runq->current) == thread);
}

int
thread_get_affinity (const struct thread *thread, struct cpumap *cpumap)
{
  if (! thread)
    return (EINVAL);

  thread_preempt_disable ();

  unsigned long flags;
  _Auto runq = thread_lock_runq ((struct thread *) thread, &flags);

  cpumap_copy (cpumap, &thread->cpumap);
  thread_unlock_runq (runq, flags);
  thread_preempt_enable ();
  return (0);
}

int
thread_set_affinity (struct thread *thread, const struct cpumap *cpumap)
{
  if (! thread)
    return (EINVAL);

  thread_preempt_disable ();

  unsigned long flags;
  _Auto runq = thread_lock_runq (thread, &flags);
  int error;

  if (thread == runq->idler ||
      thread == runq->balancer ||
      thread->state == THREAD_DEAD)
    error = EINVAL;
  else if (cpumap_intersects (&thread->cpumap, cpumap))
    { // The desired CPU map intersects the current one.
      error = 0;
      cpumap_copy (&thread->cpumap, cpumap);
    }
  else if (thread->pin_level != 0)
    // The thread is pinned, and cannot be migrated to a different CPU.
    error = EAGAIN;
  else
    { // At this point, we know the thread must be migrated.
      cpumap_copy (&thread->cpumap, cpumap);

      if (thread == runq->current)
        {
          if (runq == thread_runq_local ())
            runq = thread_runq_schedule (runq);
          else
            {
              thread_set_flag (thread, THREAD_YIELD);
              cpu_send_thread_schedule (thread_runq_cpu (runq));
            }
        }

      error = 0;
    }

  thread_unlock_runq (runq, flags);
  thread_preempt_enable ();
  return (error);
}
