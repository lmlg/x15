/*
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
 * This test creates a thread that tests cross-calls for all combinations
 * of processors. This thread sequentially creates other threads that are
 * bound to a single processor, and perform cross-calls to all processors,
 * including the local one.
 */

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include <kern/cpumap.h>
#include <kern/error.h>
#include <kern/init.h>
#include <kern/log.h>
#include <kern/panic.h>
#include <kern/thread.h>
#include <kern/xcall.h>

#include <test/test.h>

struct test_data
{
  uint32_t cpu;
  bool done;
};

static void
test_fn (void *arg)
{
  assert (thread_interrupted ());

  struct test_data *data = arg;
  if (data->cpu != cpu_id ())
    panic ("test: invalid cpu");

  log_info ("function called, running on cpu%u\n", cpu_id ());
  data->done = true;
}

static void
test_once (uint32_t cpu)
{
  struct test_data data = { .cpu = cpu, .done = false };
  log_info ("cross-call: cpu%u -> cpu%u:\n", cpu_id (), cpu);
  xcall_call (test_fn, &data, cpu);

  if (!data.done)
    panic ("test: xcall failed");
}

static void
test_run_cpu (void *arg __unused)
{
  for (uint32_t i = cpu_count () - 1; i < cpu_count (); --i)
    test_once (i);
}

static void
test_run (void *arg __unused)
{
  struct cpumap *cpumap;
  int error = cpumap_create (&cpumap);
  error_check (error, "cpumap_create");

  for (uint32_t i = 0; i < cpu_count (); i++)
    {
      /*
       * Send IPIs from CPU 1 first, in order to better trigger any
       * initialization race that may prevent correct IPI transmission.
       * This assumes CPUs are initialized sequentially, and that CPU 1
       * may have finished initialization much earlier than the last CPU.
       * CPU 0 isn't used since it's the one normally initializing remote
       * CPUs.
       */
      uint32_t cpu = (1 + i) % cpu_count();

      cpumap_zero (cpumap);
      cpumap_set (cpumap, cpu);

      char name[THREAD_NAME_SIZE];
      snprintf (name, sizeof (name), THREAD_KERNEL_PREFIX "test_run/%u", cpu);

      struct thread_attr attr;
      thread_attr_init (&attr, name);
      thread_attr_set_cpumap (&attr, cpumap);

      struct thread *thread;
      error = thread_create (&thread, &attr, test_run_cpu, NULL);
      error_check (error, "thread_create");
      thread_join (thread);
    }

  cpumap_destroy (cpumap);
  log_info ("test (xcall): done");
}

static void
async_xcall_test_fn (void *arg)
{
  log_info ("async xcall: %d\n", *(int *)arg);
  *(int *)arg = -1;
}

static void
test_async_xcall_run (void *arg __unused)
{
  struct xcall_async async;
  int value = 42;

  xcall_async_init (&async, async_xcall_test_fn, &value, 0);
  xcall_async_call (&async);
  xcall_async_wait (&async);

  assert (value == -1);
  log_info ("test (async-xcall): done");
}

static void
test_async_xcall (void)
{
  struct cpumap *cpumap;
  if (cpumap_create (&cpumap) != 0)
    {
      log_err ("failed to allocate cpumap");
      return;
    }

  struct thread_attr attr;
  thread_attr_init (&attr, THREAD_KERNEL_PREFIX "test_asyncx");

  cpumap_zero (cpumap);
  cpumap_set (cpumap, 1);
  thread_attr_set_cpumap (&attr, cpumap);
  thread_attr_set_detached (&attr);
  if (thread_create (NULL, &attr, test_async_xcall_run, NULL) != 0)
    log_err ("failed to create thread for async xcall");
}

TEST_ENTRY_INIT (xcall)
{
  struct thread_attr attr;
  thread_attr_init (&attr, THREAD_KERNEL_PREFIX "test_xcall");
  thread_attr_set_detached (&attr);
  int error = thread_create (NULL, &attr, test_run, NULL);
  error_check (error, "thread_create");

  if (cpu_count () > 1)
    test_async_xcall ();

  return (TEST_OK);
}
