/*
 * Copyright (c) 2017 Richard Braun.
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

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <kern/arg.h>
#include <kern/init.h>
#include <kern/console.h>
#include <kern/list.h>
#include <kern/log.h>
#include <kern/mutex.h>
#include <kern/spinlock.h>
#include <kern/thread.h>
#include <machine/boot.h>
#include <machine/cpu.h>

struct console_waiter
{
  struct list node;
  struct thread *thread;
};

// Registered consoles.
static struct list console_devs;

// Active console device.
static struct console *console_dev;

static const char *console_name __initdata;

static bool __init
console_name_match (const char *name)
{
  return (!console_name || strcmp (console_name, name) == 0);
}

void __init
console_init (struct console *console, const char *name,
              const struct console_ops *ops)
{
  assert (ops);

  spinlock_init (&console->lock);
  console->ops = ops;
  cbuf_init (&console->recvbuf, console->buffer, sizeof (console->buffer));
  list_init (&console->waiters);
  strlcpy (console->name, name, sizeof (console->name));
}

static int
console_process_ctrl_char (struct console *console, char c)
{
  switch (c)
    {
      case CONSOLE_SCROLL_UP:
      case CONSOLE_SCROLL_DOWN:
        break;
      default:
        return (EINVAL);
    }

  console->ops->puts (console, &c, 1);
  return (0);
}

static size_t
console_read_nolock (struct console *console, char *s, size_t size)
{
  struct console_waiter waiter = { .thread = thread_self () };
  list_insert_tail (&console->waiters, &waiter.node);

  while (1)
    {
      int error = cbuf_pop (&console->recvbuf, s, &size);

      if (! error)
        {
          size_t nc = 0;
          for (size_t i = 0; i < size; ++i)
            if (console_process_ctrl_char (console, s[i]) == 0)
              nc++;

          size -= nc;
          if (size)
            break;
        }

      thread_timedsleep (&console->lock, console, "consgetc", 1000);
    }

  list_remove (&waiter.node);
  return (size);
}

static int __init
console_bootstrap (void)
{
  list_init (&console_devs);
  console_name = arg_value ("console");
  return (0);
}

INIT_OP_DEFINE (console_bootstrap,
                INIT_OP_DEP (arg_setup, true),
                INIT_OP_DEP (log_setup, true));

static int __init
console_setup (void)
{
  return (0);
}

INIT_OP_DEFINE (console_setup,
                INIT_OP_DEP (boot_setup_console, true),
                INIT_OP_DEP (thread_setup, true));

void __init
console_register (struct console *console)
{
  assert (console->ops);
  list_insert_tail (&console_devs, &console->node);

  if (!console_dev && console_name_match (console->name))
    console_dev = console;

  log_info ("console: %s registered", console->name);
  if (console == console_dev)
    log_info ("console: %s selected as active console", console->name);
}

void
console_intr (struct console *console, const char *s)
{
  assert (thread_check_intr_context ());

  if (*s == '\0')
    return;

  SPINLOCK_GUARD (&console->lock, false);

  for (; *s; ++s)
    {
      if (cbuf_size (&console->recvbuf) == cbuf_capacity (&console->recvbuf))
        return;

      cbuf_pushb (&console->recvbuf, *s, false);
    }

  struct list *node = list_first (&console->waiters);
  if (node)
    thread_wakeup (list_entry(node, struct console_waiter, node)->thread);
}

void
console_putchar (char c)
{
  console_puts (&c, 1);
}

char
console_getchar (void)
{
  char c;

  if (!console_gets (&c, 1))
    c = EOF;

  return (c);
}

void
console_puts_nolock (const char *s, size_t size)
{
  if (console_dev)
    console_dev->ops->puts (console_dev, s, size);
}

void
console_puts (const char *s, size_t size)
{
  unsigned long flags;

  console_lock (&flags);
  console_puts_nolock (s, size);
  console_unlock (flags);
}

size_t
console_gets_nolock (char *s, size_t size)
{
  return (console_dev ? console_read_nolock (console_dev, s, size) : 0);
}

size_t
console_gets (char *s, size_t size)
{
  unsigned long flags;

  console_lock (&flags);
  size = console_gets_nolock (s, size);
  console_unlock (flags);

  return (size);
}

void
console_lock (unsigned long *flags)
{
  if (console_dev)
    spinlock_lock_intr_save (&console_dev->lock, flags);
}

void
console_unlock (unsigned long flags)
{
  if (console_dev)
    spinlock_unlock_intr_restore (&console_dev->lock, flags);
}
