/*
 * Copyright (c) 2017-2019 Richard Braun.
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
 * This test module is a stress test, expected to never terminate, of the
 * timed lock functionality provided by the mutex implementations. The
 * two conditions for success are :
 *  - no assertion triggered
 *  - all debugging system counters of the selected mutex implementation
 *    must be non-zero after some time.
 *
 * The system counters are meant to perform simple code coverage, asserting
 * all the tricky code paths are taken at least once.
 */

#include <assert.h>
#include <stddef.h>
#include <stdio.h>

#include <kern/atomic.h>
#include <kern/clock.h>
#include <kern/error.h>
#include <kern/init.h>
#include <kern/kmem.h>
#include <kern/log.h>
#include <kern/mutex.h>
#include <kern/panic.h>
#include <kern/syscnt.h>
#include <kern/thread.h>
#include <kern/timer.h>

#include <test/test.h>

#define TEST_MIN_CPUS   3

#define TEST_REPORT_INTERVAL   10000

struct test
{
  struct mutex mutex;
  uint32_t counter;
};

static struct timer test_timer;

static void
test_run (void *arg)
{
  struct test *test = arg;
  for (uint32_t counter = 1 ; ; ++counter)
    {
      if ((counter % 1024) == 0)
        printf ("%s ", thread_self()->name);

      int error = mutex_timedlock (&test->mutex, clock_get_time () + 1);
      if (error)
        {
          thread_delay (1, false);
          continue;
        }

      uint32_t prev = atomic_add (&test->counter, 1, ATOMIC_SEQ_CST);
      if (prev)
        break;
      else if ((counter % 2) == 0)
        cpu_delay (clock_ticks_to_ms (1) * 1000);
      else
        thread_delay (1, false);

      prev = atomic_sub (&test->counter, 1, ATOMIC_SEQ_CST);
      if (prev != 1)
        break;

      mutex_unlock (&test->mutex);

      if ((counter % 2) == 0)
        thread_delay (1, false);
    }

  panic ("test: invalid counter value (%u)", test->counter);
}

static struct test*
test_create (uint32_t nr_threads)
{
  assert (nr_threads);

  struct test *test = kmem_alloc (sizeof (*test));
  if (! test)
    panic ("test: unable to allocate memory");

  mutex_init (&test->mutex);
  test->counter = 0;

  struct cpumap *cpumap;
  int error = cpumap_create (&cpumap);
  error_check (error, "cpumap_create");

  for (size_t i = 0; i < nr_threads; i++)
    {
      cpumap_zero (cpumap);
      cpumap_set (cpumap, i % 3);

      char name[THREAD_NAME_SIZE];
      snprintf (name, sizeof (name), THREAD_KERNEL_PREFIX "test_run:%u/%zu",
                nr_threads, i);

      struct thread_attr attr;
      thread_attr_init (&attr, name);
      thread_attr_set_detached (&attr);
      thread_attr_set_cpumap (&attr, cpumap);

      if (i < 2)
        {
          thread_attr_set_policy (&attr, THREAD_SCHED_POLICY_RR);
          thread_attr_set_priority (&attr, THREAD_SCHED_RT_PRIO_MIN + i);
        }

      error = thread_create (NULL, &attr, test_run, test);
      error_check (error, "thread_create");
    }

  return (test);
}

static void
test_report_syscnt (struct timer *timer)
{
#ifdef CONFIG_MUTEX_PI
  syscnt_info ("rtmutex", log_stream_info ());
#else
  syscnt_info ("mutex", log_stream_info ());
#endif

  timer_schedule (timer, timer_get_time (timer) +
                         clock_ticks_from_ms (TEST_REPORT_INTERVAL));
}

TEST_ENTRY_INIT (mutex)
{
  if (cpu_count () < TEST_MIN_CPUS)
    {
      log_err ("test: at least %u processors are required", TEST_MIN_CPUS);
      return (TEST_SKIPPED);
    }

  test_create (1);
  test_create (2);
  test_create (3);
  test_create (10);

  timer_init (&test_timer, test_report_syscnt, TIMER_DETACHED);
  timer_schedule (&test_timer, clock_get_time () +
                               clock_ticks_from_ms (TEST_REPORT_INTERVAL));

  return (TEST_OK);
}
