/*
 * Copyright (c) 2012-2018 Richard Braun.
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
 * The thread module aims at providing an interface suitable to implement
 * POSIX scheduling policies. As such, it provides scheduling classes and
 * policies that closely match the standard ones. The "real-time" policies
 * (FIFO and RR) directly map the first-in first-out (SCHED_FIFO) and
 * round-robin (SCHED_RR) policies, while the "fair-scheduling" policy (FS)
 * can be used for the normal SCHED_OTHER policy. The idle policy is reserved
 * for idling kernel threads.
 *
 * By convention, the name of a kernel thread is built by concatenating the
 * kernel name and the name of the start function, separated with an underscore.
 * Threads that are bound to a processor also include the "/cpu_id" suffix.
 * For example, "x15_thread_balance/1" is the name of the inter-processor
 * balancer thread of the second processor.
 */

#ifndef KERN_THREAD_H
#define KERN_THREAD_H

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdnoreturn.h>

#include <kern/atomic.h>
#include <kern/init.h>
#include <kern/cpumap.h>
#include <kern/kernel.h>
#include <kern/macros.h>
#include <kern/spinlock_types.h>
#include <kern/turnstile_types.h>
#include <machine/cpu.h>
#include <machine/tcb.h>

/*
 * Thread structure.
 */
struct thread;

/*
 * The global priority of a thread is meant to be compared against
 * another global priority to determine which thread has higher priority.
 */
struct thread_sched_data {
    unsigned char sched_policy;
    unsigned char sched_class;
    unsigned short priority;
    unsigned int global_priority;
};

/*
 * Thread name buffer size.
 */
#define THREAD_NAME_SIZE 32

#include <kern/thread_i.h>

#define THREAD_KERNEL_PREFIX KERNEL_NAME "_"

/*
 * Thread states.
 */
#define THREAD_RUNNING      0
#define THREAD_SLEEPING     1
#define THREAD_DEAD         2
#define THREAD_SUSPENDED    3

/*
 * Scheduling policies.
 *
 * The idle policy is reserved for the per-CPU idle threads.
 */
#define THREAD_SCHED_POLICY_FIFO    0
#define THREAD_SCHED_POLICY_RR      1
#define THREAD_SCHED_POLICY_FS      2
#define THREAD_SCHED_POLICY_IDLE    3
#define THREAD_NR_SCHED_POLICIES    4

/*
 * Real-time priority properties.
 */
#define THREAD_SCHED_RT_PRIO_MIN        0
#define THREAD_SCHED_RT_PRIO_MAX        31

/*
 * Fair-scheduling priority properties.
 */
#define THREAD_SCHED_FS_PRIO_MIN        0
#define THREAD_SCHED_FS_PRIO_DEFAULT    20
#define THREAD_SCHED_FS_PRIO_MAX        39

/*
 * Thread creation attributes.
 */
struct thread_attr {
    const char *name;
    unsigned long flags;
    struct cpumap *cpumap;
    struct task *task;
    unsigned char policy;
    unsigned short priority;
};

/*
 * Initialize thread creation attributes with default values.
 *
 * It is guaranteed that these default values include :
 *  - thread is joinable
 *  - no processor affinity
 *  - task is inherited from parent thread
 *  - policy is fair-scheduling
 *  - priority is fair-scheduling default
 *
 * If the policy is changed, the priority, if applicable, must be updated
 * as well.
 */
static inline void
thread_attr_init(struct thread_attr *attr, const char *name)
{
    attr->name = name;
    attr->flags = 0;
    attr->cpumap = NULL;
    attr->task = NULL;
    attr->policy = THREAD_SCHED_POLICY_FS;
    attr->priority = THREAD_SCHED_FS_PRIO_DEFAULT;
}

static inline void
thread_attr_set_detached(struct thread_attr *attr)
{
    attr->flags |= THREAD_ATTR_DETACHED;
}

static inline void
thread_attr_set_cpumap(struct thread_attr *attr, struct cpumap *cpumap)
{
    attr->cpumap = cpumap;
}

static inline void
thread_attr_set_task(struct thread_attr *attr, struct task *task)
{
    attr->task = task;
}

static inline void
thread_attr_set_policy(struct thread_attr *attr, unsigned char policy)
{
    attr->policy = policy;
}

static inline void
thread_attr_set_priority(struct thread_attr *attr, unsigned short priority)
{
    attr->priority = priority;
}

/*
 * Thread entry point.
 *
 * Loaded TCBs are expected to call this function with interrupts disabled.
 */
void thread_main(void (*fn)(void *), void *arg);

/*
 * Initialization of the thread module on APs.
 */
void thread_ap_setup(void);

/*
 * Create a thread.
 *
 * Creation attributes must be passed, but some of them may be NULL, in which
 * case the value is inherited from the caller. The name attribute must not be
 * NULL.
 *
 * If successful, and if the caller passed a non-NULL thread pointer, it is
 * filled with the address of the newly created thread.
 */
int thread_create(struct thread **threadp, const struct thread_attr *attr,
                  void (*fn)(void *), void *arg);

/*
 * Terminate the calling thread.
 */
noreturn void thread_exit(void);

/*
 * Wait for the given thread to terminate and release its resources.
 */
void thread_join(struct thread *thread);

/*
 * Make the current thread sleep while waiting for an event.
 *
 * The interlock is used to synchronize the thread state with respect to
 * wake-ups, i.e. a wake-up request sent by another thread cannot be missed
 * if that thread is holding the interlock.
 *
 * As a special exception, threads that use preemption as a synchronization
 * mechanism can ommit the interlock and pass a NULL pointer instead.
 * In any case, the preemption nesting level must strictly be one when calling
 * this function.
 *
 * The wait channel describes the reason why the thread is sleeping. The
 * address should refer to a relevant synchronization object, normally
 * containing the interlock, but not necessarily.
 *
 * When bounding the duration of the sleep, the caller must pass an absolute
 * time in ticks, and ETIMEDOUT is returned if that time is reached before
 * the thread is awaken.
 *
 * Implies a memory barrier.
 */
void thread_sleep(struct spinlock *interlock, const void *wchan_addr,
                  const char *wchan_desc);
int thread_timedsleep(struct spinlock *interlock, const void *wchan_addr,
                      const char *wchan_desc, uint64_t ticks);

/*
 * Schedule a thread for execution on a processor.
 *
 * If the target thread is NULL, the calling thread, or already in the
 * running state, or in the suspended state, no action is performed and
 * EINVAL is returned.
 *
 * TODO Describe memory ordering with regard to thread_sleep().
 */
int thread_wakeup(struct thread *thread);

/*
 * Suspend a thread.
 *
 * A suspended thread may only be resumed by calling thread_resume().
 *
 * This operation is asynchronous, i.e. the caller must not expect the target
 * thread to be suspended on return.
 *
 * If attempting to suspend core system threads, the request is ignored and
 * EINVAL is returned.
 */
int thread_suspend(struct thread *thread);

/*
 * Resume a thread.
 *
 * This call is equivalent to thread_wakeup(), with the exception that
 * it may also wake up suspended threads.
 */
int thread_resume(struct thread *thread);

/*
 * Suspend execution of the calling thread.
 */
void thread_delay(uint64_t ticks, bool absolute);

/*
 * Start running threads on the local processor.
 *
 * Interrupts must be disabled when calling this function.
 */
noreturn void thread_run_scheduler(void);

/*
 * Make the calling thread release the processor.
 *
 * This call does nothing if preemption is disabled, or the scheduler
 * determines the caller should continue to run (e.g. it's currently the only
 * runnable thread).
 *
 * Implies a full memory barrier if a context switch occurred.
 */
void thread_yield(void);

/*
 * Report a scheduling interrupt from a remote processor.
 */
void thread_schedule_intr(void);

/*
 * Report a periodic event on the current processor.
 *
 * Interrupts and preemption must be disabled when calling this function.
 */
void thread_report_periodic_event(void);

/*
 * Set thread scheduling parameters.
 */
void thread_setscheduler(struct thread *thread, unsigned char policy,
                         unsigned short priority);

/*
 * Variant used for priority inheritance.
 *
 * The caller must hold the turnstile thread data lock and no turnstile
 * locks when calling this function.
 */
void thread_pi_setscheduler(struct thread *thread, unsigned char policy,
                            unsigned short priority);

static inline void
thread_ref(struct thread *thread)
{
    unsigned long nr_refs;

    nr_refs = atomic_fetch_add(&thread->nr_refs, 1UL, ATOMIC_RELAXED);
    assert(nr_refs != (unsigned long)-1);
}

static inline void
thread_unref(struct thread *thread)
{
    unsigned long nr_refs;

    nr_refs = atomic_fetch_sub(&thread->nr_refs, 1UL, ATOMIC_ACQ_REL);
    assert(nr_refs != 0);

    if (nr_refs == 1) {
        thread_terminate(thread);
    }
}

static inline const void *
thread_wchan_addr(const struct thread *thread)
{
    return thread->wchan_addr;
}

static inline const char *
thread_wchan_desc(const struct thread *thread)
{
    return thread->wchan_desc;
}

/*
 * Return a character representation of the state of a thread.
 */
char thread_state_to_chr(unsigned int state);

static inline const struct thread_sched_data *
thread_get_user_sched_data(const struct thread *thread)
{
    return &thread->user_sched_data;
}

static inline const struct thread_sched_data *
thread_get_real_sched_data(const struct thread *thread)
{
    return &thread->real_sched_data;
}

/*
 * If the caller requires the scheduling data to be stable, it
 * must lock one of the following objects :
 *  - the containing run queue
 *  - the per-thread turnstile data (turnstile_td)
 *
 * Both are locked when scheduling data are updated.
 */

static inline unsigned char
thread_user_sched_policy(const struct thread *thread)
{
    return thread_get_user_sched_data(thread)->sched_policy;
}

static inline unsigned char
thread_user_sched_class(const struct thread *thread)
{
    return thread_get_user_sched_data(thread)->sched_class;
}

static inline unsigned short
thread_user_priority(const struct thread *thread)
{
    return thread_get_user_sched_data(thread)->priority;
}

static inline unsigned int
thread_user_global_priority(const struct thread *thread)
{
    return thread_get_user_sched_data(thread)->global_priority;
}

static inline unsigned char
thread_real_sched_policy(const struct thread *thread)
{
    return thread_get_real_sched_data(thread)->sched_policy;
}

static inline unsigned char
thread_real_sched_class(const struct thread *thread)
{
    return thread_get_real_sched_data(thread)->sched_class;
}

static inline unsigned short
thread_real_priority(const struct thread *thread)
{
    return thread_get_real_sched_data(thread)->priority;
}

static inline unsigned int
thread_real_global_priority(const struct thread *thread)
{
    return thread_get_real_sched_data(thread)->global_priority;
}

/*
 * Return a string representation of the scheduling class of a thread.
 */
const char * thread_sched_class_to_str(unsigned char sched_class);

static inline struct tcb *
thread_get_tcb(struct thread *thread)
{
    return &thread->tcb;
}

static inline struct thread *
thread_from_tcb(struct tcb *tcb)
{
    return structof(tcb, struct thread, tcb);
}

static inline struct thread *
thread_self(void)
{
    return thread_from_tcb(tcb_current());
}

/*
 * Main scheduler invocation call.
 *
 * Called on return from interrupt or when reenabling preemption.
 */
void thread_schedule(void);

/*
 * Sleep queue lending functions.
 */

static inline struct sleepq *
thread_sleepq_lend(void)
{
    struct sleepq *sleepq;

    sleepq = thread_self()->priv_sleepq;
    assert(sleepq != NULL);
    thread_self()->priv_sleepq = NULL;
    return sleepq;
}

static inline void
thread_sleepq_return(struct sleepq *sleepq)
{
    assert(sleepq != NULL);
    assert(thread_self()->priv_sleepq == NULL);
    thread_self()->priv_sleepq = sleepq;
}

/*
 * Turnstile lending functions.
 */

static inline struct turnstile *
thread_turnstile_lend(void)
{
    struct turnstile *turnstile;

    turnstile = thread_self()->priv_turnstile;
    assert(turnstile != NULL);
    thread_self()->priv_turnstile = NULL;
    return turnstile;
}

static inline void
thread_turnstile_return(struct turnstile *turnstile)
{
    assert(turnstile != NULL);
    assert(thread_self()->priv_turnstile == NULL);
    thread_self()->priv_turnstile = turnstile;
}

static inline struct turnstile_td *
thread_turnstile_td(struct thread *thread)
{
    return &thread->turnstile_td;
}

/*
 * Priority propagation functions.
 */

static inline bool
thread_priority_propagation_needed(void)
{
    return thread_self()->propagate_priority;
}

static inline void
thread_set_priority_propagation_needed(void)
{
    thread_self()->propagate_priority = true;
}

void thread_propagate_priority(void);

/*
 * Migration control functions.
 *
 * Functions that change the migration state are implicit compiler barriers.
 */

static inline int
thread_pinned(void)
{
    return thread_self()->pin_level != 0;
}

static inline void
thread_pin(void)
{
    struct thread *thread;

    thread = thread_self();
    thread->pin_level++;
    assert(thread->pin_level != 0);
    barrier();
}

static inline void
thread_unpin(void)
{
    struct thread *thread;

    barrier();
    thread = thread_self();
    assert(thread->pin_level != 0);
    thread->pin_level--;
}

/*
 * Preemption control functions.
 *
 * Functions that change the preemption state are implicit compiler barriers.
 */

static inline int
thread_preempt_enabled(void)
{
    return thread_self()->preempt_level == 0;
}

static inline void
thread_preempt_disable(void)
{
    struct thread *thread;

    thread = thread_self();
    thread->preempt_level++;
    assert(thread->preempt_level != 0);
    barrier();
}

static inline void
thread_preempt_enable_no_resched(void)
{
    struct thread *thread;

    barrier();
    thread = thread_self();
    assert(thread->preempt_level != 0);
    thread->preempt_level--;

    /*
     * Don't perform priority propagation here, because this function is
     * called on return from interrupt, where the transient state may
     * incorrectly trigger it.
     */
}

static inline void
thread_preempt_enable(void)
{
    thread_preempt_enable_no_resched();

    if (thread_priority_propagation_needed()
        && thread_preempt_enabled()) {
        thread_propagate_priority();
    }

    thread_schedule();
}

static inline void
thread_preempt_disable_intr_save(unsigned long *flags)
{
    thread_preempt_disable();
    cpu_intr_save(flags);
}

static inline void
thread_preempt_enable_intr_restore(unsigned long flags)
{
    cpu_intr_restore(flags);
    thread_preempt_enable();
}

/*
 * Interrupt level control functions.
 *
 * Functions that change the interrupt level are implicit compiler barriers.
 */

static inline bool
thread_interrupted(void)
{
    return thread_self()->intr_level != 0;
}

static inline bool
thread_check_intr_context(void)
{
    return thread_interrupted()
           && !cpu_intr_enabled()
           && !thread_preempt_enabled();
}

static inline void
thread_intr_enter(void)
{
    struct thread *thread;

    thread = thread_self();

    if (thread->intr_level == 0) {
        thread_preempt_disable();
    }

    thread->intr_level++;
    assert(thread->intr_level != 0);
    barrier();
}

static inline void
thread_intr_leave(void)
{
    struct thread *thread;

    barrier();
    thread = thread_self();
    assert(thread->intr_level != 0);
    thread->intr_level--;

    if (thread->intr_level == 0) {
        thread_preempt_enable_no_resched();
    }
}

/*
 * RCU functions.
 */

static inline struct rcu_reader *
thread_rcu_reader(struct thread *thread)
{
    return &thread->rcu_reader;
}

/*
 * Thread-specific data functions.
 */

#if CONFIG_THREAD_MAX_TSD_KEYS != 0

/*
 * Type for thread-specific data destructor.
 */
typedef void (*thread_tsd_dtor_fn_t)(void *);

/*
 * Allocate a TSD key.
 *
 * If not NULL, the destructor is called on thread destruction on the pointer
 * associated with the allocated key.
 */
void thread_key_create(unsigned int *keyp, thread_tsd_dtor_fn_t dtor);

/*
 * Set the pointer associated with a key for the given thread.
 */
static inline void
thread_tsd_set(struct thread *thread, unsigned int key, void *ptr)
{
    thread->tsd[key] = ptr;
}

/*
 * Return the pointer associated with a key for the given thread.
 */
static inline void *
thread_tsd_get(struct thread *thread, unsigned int key)
{
    return thread->tsd[key];
}

/*
 * Set the pointer associated with a key for the calling thread.
 */
static inline void
thread_set_specific(unsigned int key, void *ptr)
{
    thread_tsd_set(thread_self(), key, ptr);
}

/*
 * Return the pointer associated with a key for the calling thread.
 */
static inline void *
thread_get_specific(unsigned int key)
{
    return thread_tsd_get(thread_self(), key);
}

#endif /* CONFIG_THREAD_MAX_TSD_KEYS != 0 */

static inline const char *
thread_name(const struct thread *thread)
{
    return thread->name;
}

#ifdef CONFIG_PERFMON
static inline struct perfmon_td *
thread_get_perfmon_td(struct thread *thread)
{
    return &thread->perfmon_td;
}
#endif /* CONFIG_PERFMON */

/*
 * Return the last CPU on which the thread has been scheduled.
 *
 * This call isn't synchronized, and the caller may obtain an outdated value.
 */
unsigned int thread_cpu(const struct thread *thread);

/*
 * Return the current state of the given thread.
 *
 * This call isn't synchronized, and the caller may obtain an outdated value.
 */
unsigned int thread_state(const struct thread *thread);

/*
 * Return true if the given thread is running.
 *
 * This call isn't synchronized, and the caller may obtain an outdated value.
 */
bool thread_is_running(const struct thread *thread);

/*
 * This init operation provides :
 *  - a dummy thread context for the BSP, allowing the use of thread_self()
 */
INIT_OP_DECLARE(thread_setup_booter);

/*
 * This init operation provides :
 *  - same as thread_setup_booter
 *  - BSP run queue initialization
 */
INIT_OP_DECLARE(thread_bootstrap);

/*
 * This init operation provides :
 *  - thread creation
 *  - module fully initialized
 */
INIT_OP_DECLARE(thread_setup);

#endif /* KERN_THREAD_H */
