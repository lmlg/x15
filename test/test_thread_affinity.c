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

struct semaphore affinity_sem;

static void
test_affinity_self(void *arg)
{
    struct cpumap *prev, *cpumap;
    int error;

    cpumap = arg;
    error = cpumap_create(&prev);
    error_check(error, "cpumap_create");

    error = thread_get_affinity(thread_self(), prev);
    error_check(error, "thread_get_affinity");

    if (cpumap_cmp(prev, cpumap) != 0) {
        panic("test: unexpected affinity map (get)");
    }

    cpumap_zero(cpumap);
    cpumap_set(cpumap, 0);

    error = thread_set_affinity(thread_self(), cpumap);
    error_check(error, "thread_set_affinity");

    semaphore_timedwait(&affinity_sem, 1);
    error = thread_get_affinity(thread_self(), prev);
    error_check(error, "thread_get_affinity (2)");

    if (cpumap_cmp(prev, cpumap) != 0) {
        panic("test: unexpected affinity map (set)");
    } else if (!cpumap_test(cpumap, thread_cpu(thread_self()))) {
        panic("test: thread not running in expected CPU");
    }

    cpumap_destroy(prev);
}

static void
test_affinity_suspended(void *arg)
{
    struct cpumap *cpumap, *prev;
    int error;

    prev = arg;
    error = cpumap_create(&cpumap);
    error_check(error, "cpumap_create");

    semaphore_wait(&affinity_sem);
    error = thread_get_affinity(thread_self(), cpumap);
    error_check(error, "thread_get_affinity");

    /* At this point, the parent thread has changed the passed
     * CPU map, and thus, they should be equal. */

    if (cpumap_cmp(cpumap, prev) != 0) {
        panic("test: unexpected affinity map");
    } else if (!cpumap_test(cpumap, thread_cpu(thread_self()))) {
        panic("test: thread not running in expected CPU");
    }

    cpumap_destroy(cpumap);
}

static void
test_run(void *arg)
{
    struct thread *thread;
    struct thread_attr attr;
    struct cpumap *cpumap;
    int error;

    (void)arg;
    if (cpu_count() < 2) {
        /* Nothing to test on uni-processor systems. */
        return;
    }

    semaphore_init(&affinity_sem, 0, 0xff);
    error = cpumap_create(&cpumap);
    error_check(error, "cpumap_create");

    cpumap_zero(cpumap);
    cpumap_set(cpumap, 1);

    thread_attr_init(&attr, "test_affinity");
    thread_attr_set_cpumap(&attr, cpumap);
    error = thread_create(&thread, &attr, test_affinity_self, cpumap);
    error_check(error, "thread_create");
    thread_join(thread);

    cpumap_zero(cpumap);
    cpumap_set(cpumap, 1);

    thread_attr_init(&attr, "test_affinity(2)");
    thread_attr_set_cpumap(&attr, cpumap);
    error = thread_create(&thread, &attr, test_affinity_suspended, cpumap);
    error_check(error, "thread_create(2)");

    while (thread_state(thread) == THREAD_RUNNING) {
        cpu_pause();
    }

    cpumap_zero(cpumap);
    cpumap_set(cpumap, 0);
    error = thread_set_affinity(thread, cpumap);
    semaphore_post(&affinity_sem);
    thread_join(thread);

    log_info("affinity test done");
}

void __init
test_setup(void)
{
    struct thread_attr attr;
    int error;

    thread_attr_init(&attr, THREAD_KERNEL_PREFIX "test_run");
    thread_attr_set_detached(&attr);
    error = thread_create(NULL, &attr, test_run, NULL);
    error_check(error, "thread_create");
}