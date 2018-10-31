/*
 * Copyright (c) 2018 Richard Braun.
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
 * This test aims to verify that threads transition state correctly when
 * suspended / resumed. It does so by making a newly created thread acquire a
 * locked spinlock, and forcing it into the 'running' state, and by having it
 * wait on a zero-valued semaphore, thus sending it to the 'sleeping' state.
 * As such, we test for the following transitions:
 *
 * CREATED -> RUNNING (*) -> SUSPENDED -> RUNNING
 * CREATED -> RUNNING -> SLEEPING (*) -> SUSPENDED -> RUNNING.
 *
 * Suspend requests are made at the states marked with an asterisk.
 *
 * In addition, this test verifies that a thread can suspend itself by creating
 * a new thread, transitioning its state to suspended and then having its child
 * resume it after ensuring its parent has already transitioned.
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
#include <kern/spinlock.h>
#include <kern/thread.h>
#include <machine/cpu.h>
#include <test/test.h>

static void
test_wait_for_state(const struct thread *thread, unsigned int state) {
    while (thread_state(thread) != state) {
        cpu_pause();
    }
}

static void
test_suspend_running(void *arg)
{
    unsigned long *lock;

    lock = arg;
    while (atomic_cas(lock, 0ul, 1ul, ATOMIC_ACQ_REL) != 0) {
        cpu_pause();
    }
}

static void
test_suspend_sleeping(void *arg)
{
    struct semaphore *sem;

    sem = arg;
    semaphore_wait(sem);
}

static void
test_resume_parent(void *arg)
{
    struct thread *thread;

    thread = arg;
    test_wait_for_state(thread, THREAD_SUSPENDED);
    thread_resume(thread);
}

static void
test_run(void *arg)
{
    struct thread *thread;
    struct thread_attr attr;
    unsigned long lock;
    struct semaphore sem;
    int error;

    (void)arg;
    thread_attr_init(&attr, "test_control");

    lock = 1ul;
    error = thread_create(&thread, &attr, test_suspend_running, &lock);
    error_check(error, "thread_create");

    test_wait_for_state(thread, THREAD_RUNNING);
    thread_suspend(thread);
    test_wait_for_state(thread, THREAD_SUSPENDED);

    atomic_store(&lock, 0ul, ATOMIC_RELEASE);
    thread_resume(thread);
    thread_join(thread);

    semaphore_init(&sem, 0);
    error = thread_create(&thread, &attr, test_suspend_sleeping, &sem);
    error_check(error, "thread_create");

    test_wait_for_state(thread, THREAD_SLEEPING);
    thread_suspend(thread);
    test_wait_for_state(thread, THREAD_SUSPENDED);
    thread_wakeup(thread);

    if (thread_state(thread) != THREAD_SUSPENDED) {
        panic("expected thread state to be suspended");
    }

    semaphore_post(&sem);
    thread_resume(thread);
    thread_join(thread);

    error = thread_create(&thread, &attr, test_resume_parent, thread_self());
    thread_suspend(thread_self());
    thread_join(thread);

    log_info("done");
}

void __init
test_setup(void)
{
    struct thread_attr attr;
    struct thread *thread;
    int error;

    thread_attr_init(&attr, THREAD_KERNEL_PREFIX "test_run");
    thread_attr_set_detached(&attr);
    error = thread_create(&thread, &attr, test_run, NULL);
    error_check(error, "thread_create");
}
