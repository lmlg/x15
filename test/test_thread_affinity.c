/*
 * Copyright (c) 2018 Agustina Arzille.
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
 */

#include <kern/atomic.h>
#include <kern/error.h>
#include <kern/log.h>
#include <kern/semaphore.h>
#include <kern/thread.h>
#include <test/test.h>

struct semaphore test_affinity_sem;

static void
test_affinity_self (void *arg)
{
  struct cpumap *prev, *cpumap = arg;
  int error = cpumap_create (&prev);
  test_assert_zero (error);

  error = thread_get_affinity (thread_self (), prev);
  test_assert_zero (error);
  test_assert_zero (cpumap_cmp (prev, cpumap));

  cpumap_zero (cpumap);
  cpumap_set (cpumap, 0);

  error = thread_set_affinity (thread_self (), cpumap);
  test_assert_zero (error);

  thread_delay (1, false);
  error = thread_get_affinity (thread_self (), prev);
  test_assert_zero (error);

  test_assert_zero (cpumap_cmp (prev, cpumap));
  test_assert_nonnull (cpumap_test (cpumap, thread_cpu (thread_self ())));

  cpumap_destroy (prev);
}

static void
test_affinity_suspended (void *arg)
{
  struct cpumap *cpumap, *prev = arg;
  int error = cpumap_create (&cpumap);
  test_assert_zero (error);

  semaphore_wait (&test_affinity_sem);
  error = thread_get_affinity (thread_self (), cpumap);
  test_assert_zero (error);

  /*
   * At this point, the parent thread has changed the passed
   * CPU map, and thus, they should be equal.
   */

  test_assert_zero (cpumap_cmp (cpumap, prev));
  test_assert_nonnull (cpumap_test (cpumap, thread_cpu (thread_self ())));

  cpumap_destroy (cpumap);
}

TEST_DEFERRED (thread_affinity)
{
  if (cpu_count () < 2)
    { // Nothing to test on uni-processor systems.
      log_err ("test (thread_affinity): not enough processors to test");
      return (TEST_SKIPPED);
    }

  semaphore_init (&test_affinity_sem, 0, 0xff);

  struct cpumap *cpumap;
  int error = cpumap_create (&cpumap);
  test_assert_zero (error);

  cpumap_zero (cpumap);
  cpumap_set (cpumap, 1);

  struct thread_attr attr;
  thread_attr_init (&attr, "test_affinity/0");
  thread_attr_set_cpumap (&attr, cpumap);

  struct thread *thread;
  error = thread_create (&thread, &attr, test_affinity_self, cpumap);
  test_assert_zero (error);
  thread_join (thread);

  cpumap_zero (cpumap);
  cpumap_set (cpumap, 1);

  thread_attr_init (&attr, "test_affinity/1");
  thread_attr_set_cpumap (&attr, cpumap);
  error = thread_create (&thread, &attr, test_affinity_suspended, cpumap);
  test_assert_zero (error);

  test_thread_wait_state (thread, THREAD_RUNNING);

  cpumap_zero (cpumap);
  cpumap_set (cpumap, 0);
  error = thread_set_affinity (thread, cpumap);
  semaphore_post (&test_affinity_sem);
  thread_join (thread);

  return (TEST_OK);
}
