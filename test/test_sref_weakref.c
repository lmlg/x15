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
 * This module is a stress test of the weak reference implementation
 * of scalable reference counters. Two threads are created. The first
 * periodically allocates a page and initializes a counter inside the
 * page, then immediately decrements the counter. The intended effect
 * is to mark the counter as dying as soon as possible. The second
 * thread continually attempts to obtain a reference, i.e. increment
 * the counter, through a weak reference. Counters are regularly
 * printed to monitor activity. There should be almost as many noref
 * calls as there are iterations in the first thread (a bit lower
 * because of the review delay) and a good amount of revives (at least
 * on multiprocessor machines) caused by successfully getting the counter
 * from the weak reference while it is marked dying but still in review.
 * Iterations in the second thread may spike when obtaining a reference
 * fails, because the error case is much faster and continues until the
 * first thread reinitializes the weak reference.
 */

#include <stddef.h>
#include <stdio.h>

#include <kern/error.h>
#include <kern/init.h>
#include <kern/log.h>
#include <kern/macros.h>
#include <kern/sref.h>
#include <kern/syscnt.h>
#include <kern/thread.h>

#include <test/test.h>

#include <vm/kmem.h>

static struct sref_weakref test_weakref;

static void
test_noref (struct sref_counter *counter)
{
  vm_kmem_free (counter, sizeof (*counter));
}

static void
test_run (void *arg __unused)
{
  for (unsigned long i = 1 ; ; i++)
    {
      struct sref_counter *counter = vm_kmem_alloc (sizeof (*counter));
      if (! counter)
        continue;

      sref_counter_init (counter, 1, &test_weakref, test_noref);
      sref_counter_dec (counter);

      for (volatile unsigned long j = 0; j < 0x20000000; j++)
        ;

      printf ("run: iterations: %lu\n", i);
      syscnt_info ("sref_epoch", log_stream_info ());
      syscnt_info ("sref_dirty_zero", log_stream_info ());
      syscnt_info ("sref_revive", log_stream_info ());
      syscnt_info ("sref_true_zero", log_stream_info ());
    }
}

static void
test_ref (void *arg __unused)
{
  for (unsigned long i = 1 ; ; i++)
    {
      struct sref_counter *counter = sref_weakref_get (&test_weakref);
      if (counter)
        sref_counter_dec (counter);

      if ((i % 100000000) == 0)
        printf ("ref: iterations: %lu\n", i);
    }
}

TEST_ENTRY_INIT (sref_weakref)
{
  struct thread_attr attr;
  thread_attr_init (&attr, THREAD_KERNEL_PREFIX "test_run");
  thread_attr_set_detached (&attr);

  int error = thread_create (NULL, &attr, test_run, NULL);
  error_check (error, "thread_create");

  thread_attr_init (&attr, THREAD_KERNEL_PREFIX "test_ref");
  thread_attr_set_detached (&attr);
  error = thread_create (NULL, &attr, test_ref, NULL);
  error_check (error, "thread_create");

  return (TEST_OK);
}
