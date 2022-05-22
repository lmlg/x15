/*
 * Copyright (c) 2014-2019 Richard Braun.
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

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <kern/adaptive_lock.h>
#include <kern/atomic.h>
#include <kern/init.h>
#include <kern/list.h>
#include <kern/log.h>
#include <kern/shell.h>
#include <kern/spinlock.h>
#include <kern/syscnt.h>
#include <kern/thread.h>

// Global list of all registered counters.
static struct list syscnt_list;
static struct adaptive_lock syscnt_lock;

#ifdef CONFIG_SHELL

static void
syscnt_shell_info (struct shell *shell, int argc, char **argv)
{
  (void) shell;
  char *prefix = argc >= 2 ? argv[1] : NULL;
  syscnt_info (prefix, shell->stream);
}

static struct shell_cmd syscnt_shell_cmds[] =
{
  SHELL_CMD_INITIALIZER ("syscnt_info", syscnt_shell_info,
                         "syscnt_info [<prefix>]",
                         "display information about system counters"),
};

static int __init
syscnt_setup_shell (void)
{
  SHELL_REGISTER_CMDS (syscnt_shell_cmds, shell_get_main_cmd_set ());
  return (0);
}

INIT_OP_DEFINE (syscnt_setup_shell,
                INIT_OP_DEP (shell_setup, true),
                INIT_OP_DEP (syscnt_setup, true));

#endif

static int __init
syscnt_setup (void)
{
  list_init (&syscnt_list);
  adaptive_lock_init (&syscnt_lock);
  return (0);
}

INIT_OP_DEFINE (syscnt_setup,
                INIT_OP_DEP (mutex_bootstrap, true),
                INIT_OP_DEP (spinlock_setup, true));

void __init
syscnt_register (struct syscnt *syscnt, const char *name)
{
#ifndef ATOMIC_HAVE_64B_OPS
  spinlock_init (&syscnt->lock);
#endif
  syscnt->value = 0;
  strlcpy (syscnt->name, name, sizeof (syscnt->name));

  ADAPTIVE_LOCK_GUARD (&syscnt_lock);
  list_insert_tail (&syscnt_list, &syscnt->node);
}

void
syscnt_info (const char *prefix, struct stream *stream)
{
  size_t prefix_length = prefix ? strlen (prefix) : 0;
  ADAPTIVE_LOCK_GUARD (&syscnt_lock);

  struct syscnt *syscnt;
  list_for_each_entry (&syscnt_list, syscnt, node)
    {
      if (prefix_length)
        {
          size_t length = strlen (syscnt->name);
          if (length < prefix_length ||
              memcmp (syscnt->name, prefix, prefix_length) != 0)
            continue;
        }
      
      fmt_xprintf (stream, "syscnt: %40s %20llu\n", syscnt->name,
                   (unsigned long long)syscnt_read (syscnt));
    }
}
