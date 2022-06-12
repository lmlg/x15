/*
 * Copyright (c) 2014 Richard Braun.
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
 * The purpose of this test module is to check that the pmap module properly
 * synchronizes page tables across processors. Two threads are created and
 * bound to processors 0 and 1 respectively. The first thread allocates a
 * page and writes it, making sure physical mappings are up-to-date locally.
 * It then transfers the page address to the second thread which validates
 * the content of the page, an operation that can only be done if the page
 * tables of the current processor have been updated.
 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <kern/condition.h>
#include <kern/cpumap.h>
#include <kern/error.h>
#include <kern/init.h>
#include <kern/mutex.h>
#include <kern/panic.h>
#include <kern/thread.h>

#include <machine/page.h>

#include <test/test.h>

#include <vm/kmem.h>

static struct condition test_condition;
static struct mutex test_lock;
static void *test_va;

static void
test_run1 (void *arg __unused)
{
  printf ("allocating page\n");
  void *ptr = vm_kmem_alloc (PAGE_SIZE);
  if (! ptr)
    {
      log_err ("(pmap_update): failed to allocate memory");
      return;
    }

  printf ("writing page\n");
  memset (ptr, 'a', PAGE_SIZE);

  printf ("passing page to second thread (%p)\n", ptr);

  mutex_lock (&test_lock);
  test_va = ptr;
  condition_signal (&test_condition);
  mutex_unlock (&test_lock);
}

static void
test_run2 (void *arg __unused)
{
  printf ("waiting for page\n");

  mutex_lock (&test_lock);
  while (! test_va)
    condition_wait (&test_condition, &test_lock);

  char *ptr = test_va;
  mutex_unlock (&test_lock);

  printf ("page received (%p), checking page\n", ptr);
  for (size_t i = 0; i < PAGE_SIZE; i++)
    if (ptr[i] != 'a')
      panic ("invalid content");

  vm_kmem_free (ptr, PAGE_SIZE);
  log_info ("test (pmap_update): OK");
}

TEST_INLINE (pmap_update)
{
  condition_init (&test_condition);
  mutex_init (&test_lock);
  test_va = NULL;

  struct cpumap *cpumap;
  int error = cpumap_create (&cpumap);
  error_check (error, "cpumap_create");

  cpumap_zero (cpumap);
  cpumap_set (cpumap, 0);

  struct thread_attr attr;
  thread_attr_init (&attr, THREAD_KERNEL_PREFIX "test_run1");
  thread_attr_set_detached (&attr);
  thread_attr_set_cpumap (&attr, cpumap);

  struct thread *thread;
  error = thread_create (&thread, &attr, test_run1, NULL);
  error_check (error, "thread_create");

  cpumap_zero (cpumap);
  cpumap_set (cpumap, 1);
  thread_attr_init (&attr, THREAD_KERNEL_PREFIX "test_run2");
  thread_attr_set_detached (&attr);
  thread_attr_set_cpumap (&attr, cpumap);
  error = thread_create (&thread, &attr, test_run2, NULL);
  error_check (error, "thread_create");

  cpumap_destroy (cpumap);
  return (TEST_RUNNING);
}
