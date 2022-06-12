/*
 * Copyright (c) 2014-2018 Remy Noel.
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
 * This module is a stress test, expected to never terminate, of the
 * performance monitoring module. It creates a control thread which
 * maintains a couple of test threads running while toggling performance
 * monitoring on them, attempting to produce many regular and corner
 * cases. In particular, the thread pool is randomly resized by destroying
 * and creating the underlying kernel threads.
 *
 * The control thread regularly prints some stats about the thread pool
 * and the associated performance monitoring events to report that it's
 * making progress.
 */

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include <kern/atomic.h>
#include <kern/clock.h>
#include <kern/error.h>
#include <kern/kmem.h>
#include <kern/log.h>
#include <kern/panic.h>
#include <kern/perfmon.h>
#include <kern/thread.h>
#include <test/test.h>

struct test_thread
{
  uint32_t id;
  struct thread *thread;
  struct perfmon_event event;
  uint32_t must_stop;
  bool monitored;
  uint64_t count;
};

struct test_controller
{
  struct test_thread **threads;
  uint32_t nr_threads;
  uint32_t monitoring_lid;
  uint32_t state_lid;
  uint64_t nr_current_events;
  uint64_t nr_total_events;
  uint64_t nr_current_threads;
  uint64_t nr_total_threads;
};

#define TEST_WAIT_DELAY_MS      100
#define TEST_LOOPS_PER_PRINT    20

#define TEST_MONITORING_SEED    12345
#define TEST_STATE_SEED         23456

static void
test_wait (void)
{
  thread_delay (clock_ticks_from_ms (TEST_WAIT_DELAY_MS), false);
}

static uint32_t
test_rand (uint32_t x)
{
  /* Basic 32-bit xorshift PRNG */
  x ^= x << 13;
  x ^= x >> 17;
  x ^= x << 5;
  return x;
}

static bool
test_thread_monitored (const struct test_thread *thread)
{
  return (thread->monitored);
}

static void
test_thread_start_monitoring (struct test_thread *thread)
{
  int error = perfmon_event_attach (&thread->event, thread->thread);
  error_check (error, __func__);
  thread->monitored = true;
}

static void
test_thread_stop_monitoring (struct test_thread *thread)
{
  thread->count += perfmon_event_read (&thread->event);
  int error = perfmon_event_detach (&thread->event);
  error_check (error, __func__);
  thread->monitored = false;
}

static void
test_thread_report (const struct test_thread *thread)
{
  log_info ("test: thread:%u count:%llu", thread->id, thread->count);
}

static void
test_run (void *arg)
{
  struct test_thread *thread = arg;
  while (1)
    if (atomic_load_rlx (&thread->must_stop))
      break;
}

static bool
test_thread_started (const struct test_thread *thread)
{
  return (thread->thread);
}

static void
test_thread_start (struct test_thread *thread)
{
  assert (!thread->monitored);
  if (test_thread_started (thread))
    return;

  thread->must_stop = 0;

  char name[THREAD_NAME_SIZE];
  snprintf (name, sizeof (name),
            THREAD_KERNEL_PREFIX "test_perfom_torture:%u", thread->id);

  struct thread_attr attr;
  thread_attr_init (&attr, name);

  int error = thread_create (&thread->thread, &attr, test_run, thread);
  error_check (error, "thread_create");
}

static void
test_thread_request_stop (struct test_thread *thread)
{
  atomic_store_rlx (&thread->must_stop, 1);
}

static void
test_thread_join (struct test_thread *thread)
{
  assert (test_thread_started (thread));
  assert (!test_thread_monitored (thread));

  thread_join (thread->thread);
  thread->thread = NULL;
}

static struct test_thread*
test_thread_create (uint32_t id)
{
  struct test_thread *thread = kmem_alloc (sizeof (*thread));
  if (! thread)
    panic ("thread allocation failed");

  thread->id = id;
  thread->thread = NULL;
  thread->must_stop = 0;
  thread->monitored = false;
  thread->count = 0;

  perfmon_event_init (&thread->event, PERFMON_EV_CYCLE, PERFMON_EF_KERN);
  test_thread_start (thread);

  return (thread);
}

static struct test_thread*
test_controller_get (struct test_controller *controller, uint32_t id)
{
  assert (id < controller->nr_threads);
  return (controller->threads[id]);
}

static struct test_thread*
test_controller_get_by_lid (struct test_controller *controller, uint32_t lid)
{
  return (test_controller_get (controller, lid % controller->nr_threads));
}

static void
test_toggle_monitoring (struct test_controller *controller,
                        struct test_thread *thread)
{
  if (!test_thread_started (thread))
    return;
  else if (thread->monitored)
    {
      test_thread_stop_monitoring (thread);
      --controller->nr_current_events;
    }
  else
    {
      test_thread_start_monitoring (thread);
      ++controller->nr_total_events;
      ++controller->nr_current_events;
    }
}

static void
test_toggle_state (struct test_controller *controller,
                   struct test_thread *thread)
{
  if (test_thread_started (thread))
    {
      /*
       * Make the thread stop asynchronously with monitoring to test
       * thread referencing.
       */
      test_thread_request_stop (thread);

      if (test_thread_monitored (thread))
        {
          test_thread_stop_monitoring (thread);
          --controller->nr_current_events;
        }

      test_thread_join (thread);
      --controller->nr_current_threads;
    }
  else
    {
      test_thread_start (thread);
      ++controller->nr_total_threads;
      ++controller->nr_current_threads;
    }
}

static void
test_controller_report (struct test_controller *controller)
{
  log_info ("test: events:%lu total:%lu threads:%lu total:%lu",
            controller->nr_current_events, controller->nr_total_events,
            controller->nr_current_threads, controller->nr_total_threads);

  for (uint32_t i = 0; i < controller->nr_threads; i++)
    test_thread_report (test_controller_get (controller, i));
}

static void
test_control (void *arg)
{
  struct test_controller *controller = arg;

  log_info ("test: %u threads", controller->nr_threads);

  for (unsigned long nr_loops = 1; /* no condition */; nr_loops++)
    {
      controller->monitoring_lid = test_rand (controller->monitoring_lid);

      struct test_thread *thread =
        test_controller_get_by_lid (controller, controller->monitoring_lid);
      test_toggle_monitoring (controller, thread);

      controller->state_lid = test_rand (controller->state_lid);
      thread = test_controller_get_by_lid (controller,
                                           controller->state_lid);
      test_toggle_state (controller, thread);
      test_wait ();

      if ((nr_loops % TEST_LOOPS_PER_PRINT) == 0)
        test_controller_report (controller);
    }
}

TEST_DEFERRED (perfmon_torture)
{
  struct test_controller *controller = kmem_alloc (sizeof (*controller));
  if (! controller)
    panic ("test: unable to create controller");

  /*
   * At least two threads are required by the monitoring/state toggling
   * operations, otherwise they always apply to the same thread, severely
   * restricting their usefulness.
   */
  controller->nr_threads = MAX (cpu_count () - 1, 2);
  controller->threads = kmem_alloc (controller->nr_threads *
                                    sizeof (*controller->threads));

  if (!controller->threads)
    panic ("test: unable to allocate thread array");

  for (uint32_t i = 0; i < controller->nr_threads; i++)
    controller->threads[i] = test_thread_create (i);

  controller->monitoring_lid = TEST_MONITORING_SEED;
  controller->state_lid = TEST_STATE_SEED;
  controller->nr_current_events = 0;
  controller->nr_total_events = 0;
  controller->nr_current_threads = controller->nr_threads;
  controller->nr_total_threads = controller->nr_threads;

  struct thread_attr attr;
  thread_attr_init (&attr, THREAD_KERNEL_PREFIX "test_perfmon_control");
  thread_attr_set_detached (&attr);
  int error = thread_create (NULL, &attr, test_control, controller);
  error_check (error, "thread_create");
  return (TEST_RUNNING);
}
