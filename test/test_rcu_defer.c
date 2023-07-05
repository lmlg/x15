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
 * This test module is a stress test, expected to never terminate, of the
 * work deferring functionality of the rcu module. It creates three
 * threads, a producer, a consumer, and a reader. The producer allocates
 * a page and writes it. It then transfers the page to the consumer, using
 * the rcu interface to update the global page pointer. Once at the
 * consumer, the rcu interface is used to defer the release of the page.
 * Concurrently, the reader accesses the page and checks its content when
 * available. These accesses are performed inside a read-side critical
 * section and should therefore never fail.
 *
 * Each thread regularly prints a string to report that it's making progress.
 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <kern/condition.h>
#include <kern/error.h>
#include <kern/kmem.h>
#include <kern/macros.h>
#include <kern/mutex.h>
#include <kern/panic.h>
#include <kern/rcu.h>
#include <kern/thread.h>
#include <kern/work.h>

#include <machine/page.h>

#include <test/test.h>

#include <vm/kmem.h>
#include <vm/page.h>

#define TEST_LOOPS_PER_PRINT   100000

struct test_pdsc
{
  struct work work;
  void *addr;
};

#define TEST_VALIDATION_BYTE   0xab

static struct mutex test_lock;
static struct condition test_condition;
static struct test_pdsc *test_pdsc;

static struct kmem_cache test_pdsc_cache;

static void
test_alloc (void *arg __unused)
{
  mutex_lock (&test_lock);

  for (size_t nr_loops = 0 ; ; ++nr_loops)
    {
      while (test_pdsc)
        condition_wait (&test_condition, &test_lock);

      struct test_pdsc *pdsc = kmem_cache_alloc (&test_pdsc_cache);

      if (pdsc)
        {
          _Auto page = vm_page_alloc (0, VM_PAGE_SEL_DIRECTMAP,
                                      VM_PAGE_KERNEL, VM_PAGE_SLEEP);
          if (page)
            pdsc->addr = memset (vm_page_direct_ptr (page),
                                 TEST_VALIDATION_BYTE, PAGE_SIZE);
        }

      rcu_store (&test_pdsc, pdsc);
      condition_signal (&test_condition);

      if ((nr_loops % TEST_LOOPS_PER_PRINT) == 0)
        printf ("alloc ");
    }
}

static void
test_deferred_free (struct work *work)
{
  struct test_pdsc *pdsc = structof (work, struct test_pdsc, work);
  if (pdsc->addr)
    vm_page_free (vm_page_lookup (vm_page_direct_pa ((uintptr_t)pdsc->addr)),
                  0, VM_PAGE_SLEEP);

  kmem_cache_free (&test_pdsc_cache, pdsc);
}

static void
test_free (void *arg __unused)
{
  mutex_lock (&test_lock);

  for (size_t nr_loops = 0 ; ; ++nr_loops)
    {
      while (! test_pdsc)
        condition_wait (&test_condition, &test_lock);

      struct test_pdsc *pdsc = test_pdsc;
      rcu_store (&test_pdsc, NULL);

      if (pdsc)
        {
          work_init (&pdsc->work, test_deferred_free);
          rcu_defer (&pdsc->work);
        }

      condition_signal (&test_condition);
      if ((nr_loops % TEST_LOOPS_PER_PRINT) == 0)
        printf ("free ");
    }
}

static void
test_read (void *arg __unused)
{
  size_t nr_loops = 0;
  while (1)
    {
      RCU_GUARD ();
      struct test_pdsc *pdsc = rcu_load (&test_pdsc);

      if (! pdsc)
        continue;

      _Auto s = (const unsigned char *)pdsc->addr;
      if (! s)
        continue;

      for (size_t i = 0; i < PAGE_SIZE; ++i)
        if (s[i] != TEST_VALIDATION_BYTE)
          panic ("invalid content");

      if ((nr_loops % TEST_LOOPS_PER_PRINT) == 0)
        printf ("read ");

      ++nr_loops;
    }
}

TEST_DEFERRED (rcu_defer)
{
  condition_init (&test_condition);
  mutex_init (&test_lock);

  kmem_cache_init (&test_pdsc_cache, "test_pdsc",
                   sizeof (struct test_pdsc), 0, NULL, 0);

  struct thread_attr attr;
  thread_attr_init (&attr, THREAD_KERNEL_PREFIX "test_rcu_alloc");
  thread_attr_set_detached (&attr);

  struct thread *thread;
  int error = thread_create (&thread, &attr, test_alloc, NULL);
  error_check (error, "thread_create");

  thread_attr_init (&attr, THREAD_KERNEL_PREFIX "test_rcu_free");
  thread_attr_set_detached (&attr);
  error = thread_create (&thread, &attr, test_free, NULL);
  error_check (error, "thread_create");

  thread_attr_init (&attr, THREAD_KERNEL_PREFIX "test_rcu_read");
  thread_attr_set_detached (&attr);
  error = thread_create (&thread, &attr, test_read, NULL);
  error_check (error, "thread_create");

  return (TEST_RUNNING);
}
