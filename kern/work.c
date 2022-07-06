/*
 * Copyright (c) 2013-2014 Richard Braun.
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
#include <errno.h>
#include <stdalign.h>
#include <stddef.h>
#include <stdio.h>

#include <kern/bitmap.h>
#include <kern/error.h>
#include <kern/init.h>
#include <kern/kmem.h>
#include <kern/list.h>
#include <kern/log.h>
#include <kern/macros.h>
#include <kern/panic.h>
#include <kern/percpu.h>
#include <kern/spinlock.h>
#include <kern/syscnt.h>
#include <kern/thread.h>
#include <kern/work.h>
#include <machine/cpu.h>

#define WORK_PRIO_NORMAL    THREAD_SCHED_FS_PRIO_DEFAULT
#define WORK_PRIO_HIGH      THREAD_SCHED_FS_PRIO_MAX

#define WORK_INVALID_CPU   ((unsigned int)-1)

// Keep at least that many threads alive when a work pool is idle.
#define WORK_THREADS_SPARE   4

/*
 * When computing the maximum number of worker threads, start with multiplying
 * the number of processors by the ratio below. If the result is greater than
 * the threshold, retry by decreasing the ratio until either the result is
 * less than the threshold or the ratio is 1.
 */
#define WORK_THREADS_RATIO       4
#define WORK_THREADS_THRESHOLD   512
#define WORK_MAX_THREADS         MAX (CONFIG_MAX_CPUS, WORK_THREADS_THRESHOLD)

// Work pool flags.
#define WORK_PF_GLOBAL      0x1   // System-wide work queue.
#define WORK_PF_HIGHPRIO    0x2   // High priority worker threads.

struct work_thread
{
  struct list node;
  struct thread *thread;
  struct work_pool *pool;
  uint32_t id;
};

/*
 * Pool of threads and works.
 *
 * Interrupts must be disabled when accessing a work pool. Holding the
 * lock is required for global pools only, whereas exclusive access on
 * per-processor pools is achieved by disabling preemption.
 *
 * There are two internal queues of pending works. When first scheduling
 * a work, it is inserted into queue0. After a periodic event, works still
 * present in queue0 are moved to queue1. If these works are still present
 * in queue1 at the next periodic event, it means they couldn't be processed
 * for a complete period between two periodic events, at which point it is
 * assumed that processing works on the same processor they were queued on
 * becomes less relevant. As a result, periodic events also trigger the
 * transfer of works from queue1 to the matching global pool. Global pools
 * only use one queue.
 */
struct work_pool
{
  __cacheline_aligned struct spinlock lock;
  int flags;
  struct work_queue queue0;
  struct work_queue queue1;
  struct work_thread *manager;
  struct syscnt sc_transfers;
  uint32_t cpu;
  uint32_t max_threads;
  uint32_t nr_threads;
  uint32_t nr_available_threads;
  struct list available_threads;
  struct list dead_threads;
  BITMAP_DECLARE (bitmap, WORK_MAX_THREADS);
};

static int work_thread_create (struct work_pool *pool, uint32_t id);

static struct work_pool work_pool_cpu_main __percpu;
static struct work_pool work_pool_cpu_highprio __percpu;
static struct work_pool work_pool_main;
static struct work_pool work_pool_highprio;

static struct kmem_cache work_thread_cache;

static unsigned int
work_pool_alloc_id (struct work_pool *pool)
{
  assert (pool->nr_threads < pool->max_threads);
  ++pool->nr_threads;
  int bit = bitmap_find_first_zero (pool->bitmap, pool->max_threads);
  assert (bit >= 0);
  bitmap_set (pool->bitmap, bit);
  return (bit);
}

static void
work_pool_free_id (struct work_pool *pool, unsigned int id)
{
  assert (pool->nr_threads != 0);
  --pool->nr_threads;
  bitmap_clear (pool->bitmap, id);
}

static unsigned int
work_pool_cpu_id (const struct work_pool *pool)
{
  assert (!(pool->flags & WORK_PF_GLOBAL));
  return (pool->cpu);
}

static unsigned int
work_pool_compute_max_threads (uint32_t nr_cpus)
{
  uint32_t ratio = WORK_THREADS_RATIO, max_threads = nr_cpus * ratio;

  for (; ratio > 1 && max_threads > WORK_THREADS_THRESHOLD;
      max_threads = nr_cpus * (--ratio))
    ;

  assert (max_threads);
  assert (max_threads <= WORK_MAX_THREADS);
  return (max_threads);
}

static void __init
work_pool_init (struct work_pool *pool)
{
  spinlock_init (&pool->lock);
  work_queue_init (&pool->queue0);
  work_queue_init (&pool->queue1);
  pool->manager = NULL;
}

static void __init
work_pool_build (struct work_pool *pool, uint32_t cpu, int flags)
{
  pool->flags = flags;
  uint32_t nr_cpus;

  if (flags & WORK_PF_GLOBAL)
    {
      nr_cpus = cpu_count ();
      pool->cpu = WORK_INVALID_CPU;
    }
  else
    {
      nr_cpus = 1;
      const char *suffix = (flags & WORK_PF_HIGHPRIO) ? "h" : "";

      char name[SYSCNT_NAME_SIZE];
      snprintf (name, sizeof (name), "work_transfers/%u%s", cpu, suffix);
      syscnt_register (&pool->sc_transfers, name);
      pool->cpu = cpu;
    }

  pool->max_threads = work_pool_compute_max_threads (nr_cpus);
  pool->nr_threads = 0;
  pool->nr_available_threads = 0;
  list_init (&pool->available_threads);
  list_init (&pool->dead_threads);
  bitmap_zero (pool->bitmap, WORK_MAX_THREADS);

  uint32_t id = work_pool_alloc_id (pool);
  if (work_thread_create (pool, id) != 0)
    panic ("work: unable to create initial worker thread");
}

static struct work_pool*
work_pool_cpu_select (int flags)
{
  return ((flags & WORK_HIGHPRIO) ?
          cpu_local_ptr (work_pool_cpu_highprio) :
          cpu_local_ptr (work_pool_cpu_main));
}

static void
work_pool_acquire (struct work_pool *pool, cpu_flags_t *flags)
{
  if (pool->flags & WORK_PF_GLOBAL)
    spinlock_lock_intr_save (&pool->lock, flags);
  else
    thread_preempt_disable_intr_save (flags);
}

static void
work_pool_release (struct work_pool *pool, cpu_flags_t flags)
{
  if (pool->flags & WORK_PF_GLOBAL)
    spinlock_unlock_intr_restore (&pool->lock, flags);
  else
    thread_preempt_enable_intr_restore (flags);
}

static int
work_pool_nr_works (const struct work_pool *pool)
{
  return (work_queue_nr_works (&pool->queue0) +
          work_queue_nr_works (&pool->queue1));
}

static struct work*
work_pool_pop_work (struct work_pool *pool)
{
  if (!(pool->flags & WORK_PF_GLOBAL) &&
      work_queue_nr_works (&pool->queue1) != 0)
    return (work_queue_pop (&pool->queue1));

  return (work_queue_pop (&pool->queue0));
}

static void
work_pool_wakeup_manager (struct work_pool *pool)
{
  if (work_pool_nr_works (pool) && pool->manager)
    thread_wakeup (pool->manager->thread);
}

static void
work_pool_shift_queues (struct work_pool *pool, struct work_queue *old_queue)
{
  assert (!(pool->flags & WORK_PF_GLOBAL));

  work_queue_transfer (old_queue, &pool->queue1);
  work_queue_transfer (&pool->queue1, &pool->queue0);
  work_queue_init (&pool->queue0);

  if (work_queue_nr_works (old_queue))
    syscnt_inc (&pool->sc_transfers);
}

static void
work_pool_push_work (struct work_pool *pool, struct work *work)
{
  work_queue_push (&pool->queue0, work);
  work_pool_wakeup_manager (pool);
}

static void
work_pool_concat_queue (struct work_pool *pool, struct work_queue *queue)
{
  work_queue_concat (&pool->queue0, queue);
  work_pool_wakeup_manager (pool);
}

static void
work_thread_destroy (struct work_thread *worker)
{
  thread_join (worker->thread);
  kmem_cache_free (&work_thread_cache, worker);
}

static void
work_process (void *arg)
{
  struct work_thread *self = arg;
  struct work_pool *pool = self->pool;
  struct spinlock *lock = (pool->flags & WORK_PF_GLOBAL) ? &pool->lock : NULL;

  cpu_flags_t flags;
  work_pool_acquire (pool, &flags);

  while (1)
    {
      if (pool->manager != NULL)
        {
          list_insert_tail (&pool->available_threads, &self->node);
          ++pool->nr_available_threads;

          do
            thread_sleep (lock, pool, "work_spr");
          while (pool->manager);

          list_remove (&self->node);
          --pool->nr_available_threads;
        }

      if (!list_empty (&pool->dead_threads))
        {
          _Auto worker = list_first_entry (&pool->dead_threads,
                                           struct work_thread, node);
          list_remove (&worker->node);
          work_pool_release (pool, flags);

          uint32_t id = worker->id;
          work_thread_destroy (worker);

          /*
           * Release worker ID last so that, if the pool is full, no new
           * worker can be created unless all the resources of the worker
           * being destroyed have been freed. This is important to enforce
           * a strict boundary on the total amount of resources allocated
           * for a pool at any time.
           */
          work_pool_acquire (pool, &flags);
          work_pool_free_id (pool, id);
          continue;
        }

      if (!work_pool_nr_works (pool))
        {
          if (pool->nr_threads > WORK_THREADS_SPARE)
            break;

          pool->manager = self;

          do
            thread_sleep (lock, pool, "work_mgr");
          while (!work_pool_nr_works (pool));

          pool->manager = NULL;
        }

      _Auto work = work_pool_pop_work (pool);
      if (work_pool_nr_works (pool))
        {
          if (pool->nr_available_threads != 0)
            {
              _Auto worker = list_first_entry (&pool->available_threads,
                                               struct work_thread, node);
              thread_wakeup (worker->thread);
            }
          else if (pool->nr_threads < pool->max_threads)
            {
              uint32_t id = work_pool_alloc_id (pool);
              work_pool_release (pool, flags);

              int error = work_thread_create (pool, id);
              work_pool_acquire (pool, &flags);

              if (error)
                {
                  work_pool_free_id (pool, id);
                  log_warning ("work: unable to create worker thread");
                }
            }
        }

      work_pool_release (pool, flags);
      work->fn (work);
      work_pool_acquire (pool, &flags);
    }

  list_insert_tail (&pool->dead_threads, &self->node);
  work_pool_release (pool, flags);
}

static int
work_thread_create (struct work_pool *pool, uint32_t id)
{
  struct work_thread *worker = kmem_cache_alloc (&work_thread_cache);
  if (! worker)
    return (ENOMEM);

  worker->pool = pool;
  worker->id = id;

  const char *suffix;
  uint16_t priority;
  int error;

  if (pool->flags & WORK_PF_HIGHPRIO)
    {
      suffix = "h";
      priority = WORK_PRIO_HIGH;
    }
  else
    {
      suffix = "";
      priority = WORK_PRIO_NORMAL;
    }

  struct cpumap *cpumap;
  char name[THREAD_NAME_SIZE];

  if (pool->flags & WORK_PF_GLOBAL)
    {
      cpumap = NULL;
      snprintf (name, sizeof (name),
                THREAD_KERNEL_PREFIX "work_process/g:%u%s",
                worker->id, suffix);
    }
  else
    {
      error = cpumap_create (&cpumap);

      if (error)
        goto error_cpumap;

      uint32_t pool_id = work_pool_cpu_id (pool);
      cpumap_zero (cpumap);
      cpumap_set (cpumap, pool_id);
      snprintf (name, sizeof (name),
                THREAD_KERNEL_PREFIX "work_process/%u:%u%s",
                pool_id, worker->id, suffix);
    }

  struct thread_attr attr;
  thread_attr_init (&attr, name);
  thread_attr_set_priority (&attr, priority);

  if (cpumap)
    thread_attr_set_cpumap (&attr, cpumap);

  error = thread_create (&worker->thread, &attr, work_process, worker);

  if (cpumap)
    cpumap_destroy (cpumap);

  if (error)
    goto error_thread;

  return (0);

error_thread:
error_cpumap:
  kmem_cache_free (&work_thread_cache, worker);
  return (error);
}

static int __init
work_bootstrap (void)
{
  work_pool_init (cpu_local_ptr (work_pool_cpu_main));
  work_pool_init (cpu_local_ptr (work_pool_cpu_highprio));
  return (0);
}

INIT_OP_DEFINE (work_bootstrap,
                INIT_OP_DEP (cpu_setup, true),
                INIT_OP_DEP (spinlock_setup, true),
                INIT_OP_DEP (thread_bootstrap, true));

static int __init
work_setup (void)
{
  kmem_cache_init (&work_thread_cache, "work_thread",
                   sizeof (struct work_thread), 0, NULL, 0);

  for (uint32_t i = 1; i < cpu_count (); i++)
    {
      work_pool_init (percpu_ptr (work_pool_cpu_main, i));
      work_pool_init (percpu_ptr (work_pool_cpu_highprio, i));
    }

  work_pool_init (&work_pool_main);
  work_pool_init (&work_pool_highprio);

  for (uint32_t i = 0; i < cpu_count (); i++)
    {
      work_pool_build (percpu_ptr (work_pool_cpu_main, i), i, 0);
      work_pool_build (percpu_ptr (work_pool_cpu_highprio, i), i,
                       WORK_PF_HIGHPRIO);
    }

  work_pool_build (&work_pool_main, WORK_INVALID_CPU, WORK_PF_GLOBAL);
  work_pool_build (&work_pool_highprio, WORK_INVALID_CPU,
                   WORK_PF_GLOBAL | WORK_PF_HIGHPRIO);

  log_info ("work: threads per pool (per-cpu/global): %u/%u, spare: %u",
            percpu_var (work_pool_cpu_main.max_threads, 0),
            work_pool_main.max_threads, WORK_THREADS_SPARE);
  return (0);
}

INIT_OP_DEFINE (work_setup,
                INIT_OP_DEP (cpu_mp_probe, true),
                INIT_OP_DEP (cpumap_setup, true),
                INIT_OP_DEP (kmem_setup, true),
                INIT_OP_DEP (log_setup, true),
                INIT_OP_DEP (spinlock_setup, true),
                INIT_OP_DEP (syscnt_setup, true),
                INIT_OP_DEP (thread_setup, true),
                INIT_OP_DEP (work_bootstrap, true));

void
work_schedule (struct work *work, int flags)
{
  THREAD_PIN_GUARD ();
  struct work_pool *pool = work_pool_cpu_select (flags);

  cpu_flags_t cpu_flags;
  work_pool_acquire (pool, &cpu_flags);
  work_pool_push_work (pool, work);
  work_pool_release (pool, cpu_flags);
}

void
work_queue_schedule (struct work_queue *queue, int flags)
{
  THREAD_PIN_GUARD ();
  struct work_pool *pool = work_pool_cpu_select (flags);

  cpu_flags_t cpu_flags;
  work_pool_acquire (pool, &cpu_flags);
  work_pool_concat_queue (pool, queue);
  work_pool_release (pool, cpu_flags);
}

void
work_report_periodic_event (void)
{
  assert (thread_check_intr_context ());

  struct work_queue queue, highprio_queue;
  work_pool_shift_queues (cpu_local_ptr (work_pool_cpu_main), &queue);
  work_pool_shift_queues (cpu_local_ptr (work_pool_cpu_highprio),
                          &highprio_queue);

  if (work_queue_nr_works (&queue))
    {
      SPINLOCK_GUARD (&work_pool_main.lock, false);
      work_pool_concat_queue (&work_pool_main, &queue);
    }

  if (work_queue_nr_works (&highprio_queue))
    {
      SPINLOCK_GUARD (&work_pool_highprio.lock, false);
      work_pool_concat_queue (&work_pool_highprio, &highprio_queue);
    }
}
