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
 * suspended / resumed. It tests the effects of calling 'thread_suspend' and
 * 'thread_resume' on a running thread and on a sleeping thread.
 */

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include <kern/error.h>
#include <kern/init.h>
#include <kern/log.h>
#include <kern/panic.h>
#include <kern/rtmutex.h>
#include <kern/spinlock.h>
#include <kern/thread.h>
#include <test/test.h>

static void
test_suspend_running(void *arg)
{
    struct spinlock *lock;

    lock = (struct spinlock *)arg;
    spinlock_lock(lock);
    spinlock_unlock(lock);
}

static void
test_suspend_sleeping(void *arg)
{
    struct rtmutex *rtmutex;

    rtmutex = (struct rtmutex *)arg;
    rtmutex_lock(rtmutex);
    rtmutex_unlock(rtmutex);
}

static void
wait_for_state(const struct thread *thread, unsigned int state) {
    while (thread_state(thread) != state) {
        cpu_pause();
    }
}

static void
test_run(void *arg)
{
    struct thread *thread;
    struct thread_attr attr;
    struct spinlock lock_1;
    struct rtmutex lock_2;
    int error;

    (void)arg;
    thread_attr_init(&attr, "test_worker");

    spinlock_init(&lock_1);
    spinlock_lock(&lock_1);
    error = thread_create(&thread, &attr, test_suspend_running, &lock_1);
    error_check(error, "thread_create");

    wait_for_state(thread, THREAD_RUNNING);
    thread_suspend(thread);
    wait_for_state(thread, THREAD_SUSPENDED);

    spinlock_unlock(&lock_1);
    thread_resume(thread);
    thread_join(thread);

    rtmutex_init(&lock_2);
    rtmutex_lock(&lock_2);
    error = thread_create(&thread, &attr, test_suspend_sleeping, &lock_2);
    error_check(error, "thread_create");

    wait_for_state(thread, THREAD_SLEEPING);
    thread_suspend(thread);
    wait_for_state(thread, THREAD_SUSPENDED);
    thread_wakeup(thread);
    assert(thread_state(thread) == THREAD_SUSPENDED);

    rtmutex_unlock(&lock_2);
    thread_resume(thread);
    thread_join(thread);

    log_info("done\n");
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
