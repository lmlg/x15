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

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <kern/cspace.h>
#include <kern/init.h>
#include <kern/kmem.h>
#include <kern/list.h>
#include <kern/log.h>
#include <kern/macros.h>
#include <kern/shell.h>
#include <kern/spinlock.h>
#include <kern/task.h>
#include <kern/thread.h>

#include <vm/map.h>

#ifdef __LP64__
  #define TASK_INFO_ADDR_FMT "%016lx"
#else
  #define TASK_INFO_ADDR_FMT "%08lx"
#endif

struct task task_kernel_task;

// Cache for allocated tasks.
static struct kmem_cache task_cache;

// Global list of tasks.
static struct list task_list;
static struct spinlock task_list_lock;

static void
task_init (struct task *task, const char *name, struct vm_map *map)
{
  kuid_head_init (&task->kuid);
  spinlock_init (&task->lock);
  list_init (&task->threads);
  task->map = map;
  strlcpy (task->name, name, sizeof (task->name));
}

#ifdef CONFIG_SHELL

static void
task_shell_info (struct shell *shell, int argc, char **argv)
{
  if (argc == 1)
    {
      task_info (NULL, shell->stream);
      return;
    }
  
  struct task *task = task_lookup (argv[1]);
  if (! task)
    {
      fmt_xprintf (shell->stream, "task not found: %s\n", argv[1]);
      return;
    }
  
  task_info (task, shell->stream);
  task_unref (task);
  return;
}

static struct shell_cmd task_shell_cmds[] =
{
  SHELL_CMD_INITIALIZER ("task_info", task_shell_info,
                         "task_info [<task_name>]",
                         "display tasks and threads"),
};

static int __init
task_setup_shell (void)
{
  SHELL_REGISTER_CMDS (task_shell_cmds, shell_get_main_cmd_set ());
  return (0);
}

INIT_OP_DEFINE (task_setup_shell,
                INIT_OP_DEP (printf_setup, true),
                INIT_OP_DEP (shell_setup, true),
                INIT_OP_DEP (task_setup, true),
                INIT_OP_DEP (thread_setup, true));

#endif

static int __init
task_setup (void)
{
  struct task *kernel_task = task_get_kernel_task ();
  kmem_cache_init (&task_cache, "task", sizeof (struct task), 0, NULL, 0);
  list_init (&task_list);
  spinlock_init (&task_list_lock);
  task_init (kernel_task, "x15", vm_map_get_kernel_map ());
  list_insert_head (&task_list, &kernel_task->node);
  return (0);
}

INIT_OP_DEFINE (task_setup,
                INIT_OP_DEP (kmem_setup, true),
                INIT_OP_DEP (spinlock_setup, true),
                INIT_OP_DEP (vm_map_setup, true));

int
task_create (struct task **taskp, const char *name)
{
  struct task *task = kmem_cache_alloc (&task_cache);
  if (! task)
    return (ENOMEM);

  struct vm_map *map;
  int error = vm_map_create (&map);
  if (error)
    goto error_map;

  task_init (task, name, map);
  error = kuid_alloc (&task->kuid, KUID_TASK);
  if (error)
    goto error_kuid;

  cspace_init (&task->caps);

  spinlock_lock (&task_list_lock);
  list_insert_tail (&task_list, &task->node);
  spinlock_unlock (&task_list_lock);

  *taskp = task;
  return (0);

error_kuid:
  vm_map_destroy (task->map);
error_map:
  kmem_cache_free (&task_cache, task);
  return (error);
}

void
task_destroy (struct task *task)
{
  spinlock_lock (&task_list_lock);
  list_remove (&task->node);
  spinlock_unlock (&task_list_lock);
  vm_map_destroy (task->map);
  cspace_destroy (&task->caps);
  kuid_remove (&task->kuid, KUID_TASK);
  kmem_cache_free (&task_cache, task);
}

struct task*
task_lookup (const char *name)
{
  SPINLOCK_GUARD (&task_list_lock);

  struct task *task;
  list_for_each_entry (&task_list, task, node)
    {
      SPINLOCK_GUARD (&task->lock);
      if (strcmp (task->name, name) == 0)
        {
          task_ref (task);
          return (task);
        }
    }

  return (NULL);
}

void
task_add_thread (struct task *task, struct thread *thread)
{
  SPINLOCK_GUARD (&task->lock);
  list_insert_tail (&task->threads, &thread->task_node);
}

void
task_remove_thread (struct task *task, struct thread *thread)
{
  spinlock_lock (&task->lock);
  list_remove (&thread->task_node);
  bool unref = list_empty (&task->threads);
  spinlock_unlock (&task->lock);

  if (unref)
    {
      // Destroy the cspace early to avoid circular references.
      cspace_destroy (&task->caps);
      task_unref (task);
    }
}

struct thread*
task_lookup_thread (struct task *task, const char *name)
{
  SPINLOCK_GUARD (&task->lock);

  struct thread *thread;
  list_for_each_entry (&task->threads, thread, task_node)
    if (strcmp (thread_name (thread), name) == 0)
      {
        thread_ref (thread);
        return (thread);
      }

  return (NULL);
}

void
task_info (struct task *task, struct stream *stream)
{
  if (! task)
    {
      SPINLOCK_GUARD (&task_list_lock);
      list_for_each_entry (&task_list, task, node)
        task_info (task, stream);

      return;
    }

  SPINLOCK_GUARD (&task->lock);
  fmt_xprintf (stream, "task: name: %s, threads:\n", task->name);

  if (list_empty (&task->threads))
    {
      stream_puts (stream, "(empty)\n");
      return;
    }

  /*
   * Don't grab any lock when accessing threads, so that the function
   * can be used to debug in the middle of most critical sections.
   * Threads are only destroyed after being removed from their task
   * so holding the task lock is enough to guarantee existence.
   */

  struct thread *thread;
  list_for_each_entry (&task->threads, thread, task_node)
    fmt_xprintf (stream, TASK_INFO_ADDR_FMT " %c %8s:" TASK_INFO_ADDR_FMT
                 " %.2s:%02hu %02u %s\n",
                 (uintptr_t)thread,
                 thread_state_to_chr (thread_state (thread)),
                 thread_wchan_desc (thread),
                 (uintptr_t)thread_wchan_addr (thread),
                 thread_sched_class_to_str (thread_user_sched_class (thread)),
                 thread_user_priority (thread),
                 thread_real_global_priority (thread),
                 thread_name (thread));
}

#define TASK_IPC_NEEDS_COPY   ((1u << TASK_IPC_GET_NAME))

static ssize_t
task_name_impl (struct task *task, char *name, bool set)
{
  SPINLOCK_GUARD (&task->lock);
  if (set)
    memcpy (task->name, name, sizeof (task->name));
  else
    memcpy (name, task->name, sizeof (task->name));

  return (0);
}

ssize_t
task_handle_msg (struct task *task, struct ipc_msg *src,
                 struct ipc_msg *dst, struct ipc_msg_data *data)
{
  struct task_ipc_msg tmsg;
  struct iovec iov = { .iov_base = &tmsg, .iov_len = sizeof (tmsg) };
  ssize_t rv = ipc_bcopyv (task_self (), src->iovs, src->iov_cnt,
                           &iov, 1, IPC_COPY_FROM);

  if (rv < 0)
    return (rv);

  switch (tmsg.op)
    {
      case TASK_IPC_GET_NAME:
      case TASK_IPC_SET_NAME:
        rv = task_name_impl (task, tmsg.name, tmsg.op == TASK_IPC_SET_NAME);
        break;
      default:
        return (-EINVAL);
    }

  if (rv >= 0 && ((1u << tmsg.op) & TASK_IPC_NEEDS_COPY))
    rv = ipc_bcopyv (task_self (), dst->iovs, dst->iov_cnt,
                     &iov, 1, IPC_COPY_TO);

  (void)data;
  return (rv < 0 ? rv : 0);
}
