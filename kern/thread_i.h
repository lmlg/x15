/*
 * Copyright (c) 2017-2018 Richard Braun.
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
 */

#ifndef KERN_THREAD_I_H
#define KERN_THREAD_I_H

#include <stdalign.h>
#include <stdbool.h>

#include <kern/atomic.h>
#include <kern/cpumap.h>
#include <kern/list_types.h>
#include <kern/perfmon_types.h>
#include <kern/rcu_types.h>
#include <kern/spinlock_types.h>
#include <kern/turnstile_types.h>
#include <machine/cpu.h>
#include <machine/tcb.h>

/*
 * Forward declarations.
 */
struct sleepq;

struct thread_runq;
struct thread_fs_runq;

/*
 * Thread flags.
 */
#define THREAD_YIELD    0x1UL /* Must yield the processor ASAP */
#define THREAD_DETACHED 0x2UL /* Resources automatically released on exit */

/*
 * Scheduling data for a real-time thread.
 */
struct thread_rt_data {
    struct list node;
    unsigned short time_slice;
};

/*
 * Scheduling data for a fair-scheduling thread.
 */
struct thread_fs_data {
    struct list group_node;
    struct list runq_node;
    struct thread_fs_runq *fs_runq;
    unsigned long round;
    unsigned short weight;
    unsigned short work;
};

/*
 * Thread structure.
 *
 * Threads don't have their own lock. Instead, the associated run queue
 * lock is used for synchronization. A number of members are thread-local
 * and require no synchronization. Others must be accessed with atomic
 * instructions.
 *
 * Locking keys :
 * (r) run queue
 * (t) turnstile_td
 * (T) task
 * (j) join_lock
 * (a) atomic
 * (-) thread-local
 * ( ) read-only
 *
 * (*) The runq member is used to determine which run queue lock must be
 * held to serialize access to the relevant members. However, it is only
 * updated while the associated run queue is locked. As a result, atomic
 * reads are only necessary outside critical sections.
 */
struct thread {
    alignas(CPU_L1_SIZE) struct tcb tcb; /* (r) */

    unsigned long nr_refs;  /* (a) */
    unsigned long flags;    /* (a) */

    /* Sleep/wake-up synchronization members */
    struct thread_runq *runq;   /* (r,*) */
    bool in_runq;               /* (r)   */
    const void *wchan_addr;     /* (r)   */
    const char *wchan_desc;     /* (r)   */
    int wakeup_error;           /* (r)   */
    unsigned int state;         /* (a,r) */

    /* Sleep queue available for lending */
    struct sleepq *priv_sleepq; /* (-) */

    /* Turnstile available for lending */
    struct turnstile *priv_turnstile;   /* (-) */

    struct turnstile_td turnstile_td;   /* (t) */

    /* True if priority must be propagated when preemption is reenabled */
    bool propagate_priority;    /* (-) */

    /* Preemption level, preemption is enabled if 0 */
    unsigned short preempt_level;   /* (-) */

    /* Pin level, migration is allowed if 0 */
    unsigned short pin_level;   /* (-) */

    /* Interrupt level, in thread context if 0 */
    unsigned short intr_level;  /* (-) */

    /* RCU per-thread data */
    struct rcu_reader rcu_reader;   /* (-) */

    /* Processors on which this thread is allowed to run */
    struct cpumap cpumap;   /* (r) */

    struct thread_sched_data user_sched_data;   /* (r,t) */
    struct thread_sched_data real_sched_data;   /* (r,t) */

    /*
     * True if the real scheduling data are not the user scheduling data.
     *
     * Note that it doesn't provide any information about priority inheritance.
     * A thread may be part of a priority inheritance chain without its
     * priority being boosted.
     */
    bool boosted;   /* (r,t) */

    /* True if the thread is marked to suspend */
    bool suspend;   /* (r) */

    union {
        struct thread_rt_data rt_data;  /* (r) */
        struct thread_fs_data fs_data;  /* (r) */
    };

    /*
     * Thread-specific data.
     *
     * TSD are reserved for application use.
     */
#if CONFIG_THREAD_MAX_TSD_KEYS != 0
    void *tsd[CONFIG_THREAD_MAX_TSD_KEYS];
#endif /* CONFIG_THREAD_MAX_TSD_KEYS != 0 */

    /*
     * Members related to termination.
     *
     * The termination protocol is made of two steps :
     *  1/ The thread exits, thereby releasing its self reference, and
     *     sets its state to dead before calling the scheduler.
     *  2/ Another thread must either already be joining, or join later.
     *     When the thread reference counter drops to zero, the terminating
     *     flag is set, and the joining thread is awaken, if any. After that,
     *     the join operation polls the state until it sees the target thread
     *     as dead, and then releases its resources.
     */
    struct thread *join_waiter;     /* (j) */
    struct spinlock join_lock;
    bool terminating;               /* (j) */

    struct task *task;              /* (T) */
    struct list task_node;          /* (T) */
    void *stack;                    /* (-) */
    char name[THREAD_NAME_SIZE];    /* ( ) */

#ifdef CONFIG_PERFMON
    struct perfmon_td perfmon_td;   /* ( ) */
#endif
};

#define THREAD_ATTR_DETACHED 0x1

void thread_terminate(struct thread *thread);

/*
 * Flag access functions.
 */

static inline void
thread_set_flag(struct thread *thread, unsigned long flag)
{
    atomic_or(&thread->flags, flag, ATOMIC_RELEASE);
}

static inline void
thread_clear_flag(struct thread *thread, unsigned long flag)
{
    atomic_and(&thread->flags, ~flag, ATOMIC_RELEASE);
}

static inline int
thread_test_flag(struct thread *thread, unsigned long flag)
{
    return (atomic_load(&thread->flags, ATOMIC_ACQUIRE) & flag) != 0;
}

#endif /* KERN_THREAD_I_H */
