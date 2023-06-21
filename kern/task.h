/*
 * Copyright (c) 2012-2019 Richard Braun.
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

#ifndef KERN_TASK_H
#define KERN_TASK_H

#include <stdint.h>

#include <kern/atomic.h>
#include <kern/cspace_types.h>
#include <kern/init.h>
#include <kern/kuid.h>
#include <kern/list.h>
#include <kern/log.h>
#include <kern/spinlock.h>
#include <kern/stream.h>
#include <kern/thread.h>

#include <vm/map.h>

// Task name buffer size.
#define TASK_NAME_SIZE   32

// Task structure.
struct task
{
  struct kuid_head kuid;
  struct spinlock lock;
  struct list node;
  struct list threads;
  struct vm_map *map;
  struct cspace caps;
  char name[TASK_NAME_SIZE];
};

// Task IPC message (TODO: Move to a specific header).
struct task_ipc_msg
{
  uint32_t size;
  int op;
  union
    {
      char name[TASK_NAME_SIZE];
    };
};

// Task IPC operations.
enum
{
  TASK_IPC_GET_NAME,
  TASK_IPC_SET_NAME,
};

static inline struct task*
task_get_kernel_task (void)
{
  extern struct task task_kernel_task;
  return (&task_kernel_task);
}

static inline uint32_t
task_get_kuid (const struct task *task)
{
  return (task->kuid.id);
}

static inline void
task_ref (struct task *task)
{
  size_t nr_refs = atomic_add_rlx (&task->kuid.nr_refs, 1);
  assert (nr_refs != (size_t)-1);
}

void task_destroy (struct task *task);

static inline void
task_unref (struct task *task)
{
  size_t nr_refs = atomic_sub_acq_rel (&task->kuid.nr_refs, 1);
  assert (nr_refs);

  if (nr_refs == 1)
    task_destroy (task);
}

static inline struct vm_map*
task_get_vm_map (const struct task *task)
{
  return (task->map);
}

static inline struct task*
task_self (void)
{
  return (thread_self()->task);
}

// Create a task.
int task_create (struct task **taskp, const char *name);

/*
 * Look up a task from its name.
 *
 * If a task is found, it gains a reference. Otherwise, NULL is returned.
 *
 * This function is meant for debugging only.
 */
struct task* task_lookup (const char *name);

// Add a thread to a task.
void task_add_thread (struct task *task, struct thread *thread);

// Remove a thread from a task.
void task_remove_thread (struct task *task, struct thread *thread);

/*
 * Look up a thread in a task from its name.
 *
 * If a thread is found, it gains a reference, Otherwise, NULL is returned.
 *
 * This function is meant for debugging only.
 */
struct thread* task_lookup_thread (struct task *task, const char *name);

// Look up a task by its KUID.
static inline struct task*
task_by_kuid (uint32_t kuid)
{
  return (kuid_find_type (kuid, struct task, kuid, KUID_TASK));
}

/*
 * Display task information.
 *
 * If task is NULL, this function displays all tasks.
 */
void task_info (struct task *task, struct stream *stream);

// Handle an IPC message on a task capability.
struct cap_iters;
struct ipc_msg_data;

ssize_t task_handle_msg (struct task *task, struct cap_iters *src,
                         struct cap_iters *dst, struct ipc_msg_data *data);

/*
 * This init operation provides :
 *  - task creation
 *  - module fully initialized
 */
INIT_OP_DECLARE (task_setup);

#endif
