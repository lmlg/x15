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
 *
 * This test checks that thread state transitions are correctly performed
 * when a thread is suspended and resumed. It does so by creating three
 * threads :
 *
 *  - The first thread spins on an atomic integer used as a lock, which
 *    puts it in the running state. The lock is released while the thread
 *    is suspended, and the thread is then resumed.
 *
 *  - The second thread waits on a zero-valued semaphore, which puts it
 *    in the sleeping state. The semaphore is signalled while the thread
 *    is suspended, and the thread is then resumed.
 *
 *  - The third suspends itself and is then resumed.
 *
 * As a result, the following transitions are tested :
 *  o CREATED -> RUNNING (*) -> SUSPENDED -> RUNNING
 *  o CREATED -> RUNNING -> SLEEPING (*) -> SUSPENDED -> RUNNING.
 *
 * (*) Step where a suspend request is made
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include <kern/atomic.h>
#include <kern/error.h>
#include <kern/init.h>
#include <kern/log.h>
#include <kern/panic.h>
#include <kern/semaphore.h>
#include <kern/thread.h>

#include <machine/cpu.h>

#include <test/test.h>

static void
test_spin (void *arg)
{
  unsigned long *lock = arg;
  while (atomic_cas (lock, 0, 1, ATOMIC_ACQ_REL) != 0)
    atomic_spin_nop ();
}

static void
test_sleep (void *arg)
{
  semaphore_wait ((struct semaphore *)arg);
}

static void
test_suspend_self (void *arg __unused)
{
  thread_suspend (thread_self ());
}

TEST_DEFERRED (thread_suspend)
{
  unsigned long lock = 1;
  struct thread_attr attr;
  struct thread *thread;

  thread_attr_init (&attr, "test_spin");
  int error = thread_create (&thread, &attr, test_spin, &lock);
  error_check (error, "thread_create");

  test_thread_wait_state (thread, THREAD_RUNNING);
  thread_suspend (thread);
  test_thread_wait_state (thread, THREAD_SUSPENDED);

  atomic_store_rel (&lock, 0);
  thread_resume (thread);
  thread_join (thread);

  struct semaphore sem;
  semaphore_init (&sem, 0, 0xff);
  thread_attr_init (&attr, "test_sleep");
  error = thread_create (&thread, &attr, test_sleep, &sem);
  error_check (error, "thread_create");

  test_thread_wait_state (thread, THREAD_SLEEPING);
  thread_suspend (thread);
  test_thread_wait_state (thread, THREAD_SUSPENDED);
  thread_wakeup (thread);

  if (thread_state (thread) != THREAD_SUSPENDED)
    panic ("test: unexpected thread state");

  semaphore_post (&sem);
  thread_resume (thread);
  thread_join (thread);

  thread_attr_init (&attr, "test_suspend_self");
  error = thread_create (&thread, &attr, test_suspend_self, NULL);
  test_thread_wait_state (thread, THREAD_SUSPENDED);
  thread_resume (thread);
  thread_join (thread);

  return (TEST_OK);
}
