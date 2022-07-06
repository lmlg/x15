/*
 * Copyright (c) 2017-2019 Richard Braun.
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
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <kern/arg.h>
#include <kern/bulletin.h>
#include <kern/init.h>
#include <kern/log.h>
#include <kern/macros.h>
#include <kern/mbuf.h>
#include <kern/panic.h>
#include <kern/shell.h>
#include <kern/spinlock.h>
#include <kern/thread.h>
#include <machine/boot.h>
#include <machine/cpu.h>

#define LOG_BUFFER_SIZE   16384

#if !ISP2(LOG_BUFFER_SIZE)
  #error "log buffer size must be a power-of-two"
#endif

#define LOG_MSG_SIZE   128

#define LOG_PRINT_LEVEL   LOG_INFO

static struct thread *log_thread;

static struct mbuf log_mbuf;
static char log_buffer[LOG_BUFFER_SIZE];

static unsigned int log_nr_overruns;

static struct bulletin log_bulletin;

/*
 * Global lock.
 *
 * Interrupts must be disabled when holding this lock.
 */
static struct spinlock log_lock;

struct log_record
{
  uint8_t level;
  char msg[LOG_MSG_SIZE];
};

struct log_consumer
{
  struct mbuf *mbuf;
  size_t index;
};

static void
log_consumer_init (struct log_consumer *ctx, struct mbuf *mbuf)
{
  ctx->mbuf = mbuf;
  ctx->index = mbuf_start (mbuf);
}

static int
log_consumer_pop (struct log_consumer *ctx, struct log_record *record)
{
  while (1)
    {
      size_t size = sizeof (*record);
      int error = mbuf_read (ctx->mbuf, &ctx->index, record, &size);

      if (error != EINVAL)
        return (error);

      ctx->index = mbuf_start (ctx->mbuf);
    }
}

static const char*
log_level2str (unsigned int level)
{
  switch (level)
    {
      case LOG_EMERG:
        return ("emerg");
      case LOG_ALERT:
        return ("alert");
      case LOG_CRIT:
        return ("crit");
      case LOG_ERR:
        return ("error");
      case LOG_WARNING:
        return ("warning");
      case LOG_NOTICE:
        return ("notice");
      case LOG_INFO:
        return ("info");
      case LOG_DEBUG:
        return ("debug");
      default:
        return (NULL);
    }
}

static void
log_print_record (const struct log_record *record, unsigned int level)
{
  if (record->level > level)
    return;

  if (record->level <= LOG_WARNING)
    printf ("%7s %s\n", log_level2str (record->level), record->msg);
  else
    printf ("%s\n", record->msg);
}

static void
log_run (void *arg __unused)
{
  bool published = false;
  cpu_flags_t flags;

  spinlock_lock_intr_save (&log_lock, &flags);

  struct log_consumer ctx;
  log_consumer_init (&ctx, &log_mbuf);

  while (1)
    {
      struct log_record record;

      while (1)
        {
          int error = log_consumer_pop (&ctx, &record);

          if (! error)
            break;
          else if (log_nr_overruns != 0)
            {
              record.level = LOG_ERR;
              snprintf (record.msg, sizeof (record.msg),
                        "log: buffer overruns, %u messages dropped",
                        log_nr_overruns);
              log_nr_overruns = 0;
              break;
            }

          if (!published)
            {
              spinlock_unlock_intr_restore (&log_lock, flags);
              bulletin_publish (&log_bulletin, 0);
              spinlock_lock_intr_save (&log_lock, &flags);
              published = true;
            }

          thread_sleep (&log_lock, &log_mbuf, "log_mbuf");
        }

      spinlock_unlock_intr_restore (&log_lock, flags);
      log_print_record (&record, LOG_PRINT_LEVEL);
      spinlock_lock_intr_save (&log_lock, &flags);
    }
}

#ifdef CONFIG_SHELL

static void
log_dump (unsigned int level)
{
  cpu_flags_t flags;
  spinlock_lock_intr_save (&log_lock, &flags);

  struct log_consumer ctx;
  log_consumer_init (&ctx, &log_mbuf);

  while (1)
    {
      struct log_record record;
      int error = log_consumer_pop (&ctx, &record);

      if (error)
        break;

      spinlock_unlock_intr_restore (&log_lock, flags);
      log_print_record (&record, level);
      spinlock_lock_intr_save (&log_lock, &flags);
    }

  spinlock_unlock_intr_restore (&log_lock, flags);
}

static void
log_shell_dump (struct shell *shell __unused, int argc, char **argv)
{
  unsigned int level;

  if (argc != 2)
    level = LOG_PRINT_LEVEL;
  else
    {
      int ret = sscanf (argv[1], "%u", &level);

      if (ret != 1 || level >= LOG_NR_LEVELS)
        {
          printf ("log: dump: invalid arguments\n");
          return;
        }
    }

  log_dump (level);
}

static struct shell_cmd log_shell_cmds[] =
{
  SHELL_CMD_INITIALIZER2 ("log_dump", log_shell_dump,
                          "log_dump [<level>]",
                          "dump the log buffer",
                          "Only records of level less than or equal to the given level"
                          " are printed. Level may be one of :\n"
                          " 0: emergency\n"
                          " 1: alert\n"
                          " 2: critical\n"
                          " 3: error\n"
                          " 4: warning\n"
                          " 5: notice\n"
                          " 6: info\n"
                          " 7: debug"),
};

static int __init
log_setup_shell (void)
{
  SHELL_REGISTER_CMDS (log_shell_cmds, shell_get_main_cmd_set ());
  return (0);
}

INIT_OP_DEFINE (log_setup_shell,
                INIT_OP_DEP (log_setup, true),
                INIT_OP_DEP (shell_setup, true));

#endif   // CONFIG_SHELL

struct logger_stream
{
  struct stream base;
  struct log_record record;
  struct spinlock lock;
  uint32_t off;
};

static size_t
logger_stream_cap (const struct logger_stream *stream)
{
  return (sizeof (stream->record.msg) - 1 - stream->off);
}

static int log_puts (const struct log_record *, int);

static void
logger_stream_write (struct stream *stream, const void *data, uint32_t bytes)
{
  _Auto logstr = structof (stream, struct logger_stream, base);
  size_t cap = logger_stream_cap (logstr);
  const char *newl = memchr (data, '\n', bytes);

  if (bytes < cap && !newl)
    {
      memcpy (logstr->record.msg + logstr->off, data, bytes);
      logstr->off += bytes;
      return;
    }

  if (newl)
    bytes = newl - (const char *) data;

  bytes = MIN (bytes, cap);
  memcpy (logstr->record.msg + logstr->off, data, bytes);
  logstr->off += bytes;
  logstr->record.msg[logstr->off] = 0;
  log_puts (&logstr->record, (int) logstr->off);
  logstr->off = 0;
}

static void
logger_stream_lock (struct stream *stream)
{
  _Auto logstr = structof (stream, struct logger_stream, base);
  spinlock_lock (&logstr->lock);
}

static void
logger_stream_unlock (struct stream *stream)
{
  _Auto logstr = structof (stream, struct logger_stream, base);
  spinlock_unlock (&logstr->lock);
}

static const struct stream_ops logger_stream_ops =
{
  .write = logger_stream_write,
  .lock = logger_stream_lock,
  .unlock = logger_stream_unlock
};

static struct logger_stream logger_streams[LOG_NR_LEVELS];

static void
logger_stream_init (struct logger_stream *stream)
{
  stream_init (&stream->base, &logger_stream_ops);
  stream->record.level = stream - &logger_streams[0];
}

struct stream*
log_stream (unsigned int level)
{
  assert (level < ARRAY_SIZE (logger_streams));
  return (&logger_streams[level].base);
}

static int __init
log_setup (void)
{
  mbuf_init (&log_mbuf, log_buffer, sizeof (log_buffer),
             sizeof (struct log_record));
  spinlock_init (&log_lock);
  bulletin_init (&log_bulletin);

  for (size_t i = 0; i < ARRAY_SIZE (logger_streams); ++i)
    logger_stream_init (&logger_streams[i]);

  boot_log_info ();
  arg_log_info ();
  cpu_log_info (cpu_current ());

  return (0);
}

INIT_OP_DEFINE (log_setup,
                INIT_OP_DEP (arg_setup, true),
                INIT_OP_DEP (cpu_setup, true),
                INIT_OP_DEP (spinlock_setup, true));

static int __init
log_start (void)
{
  struct thread_attr attr;
  thread_attr_init (&attr, THREAD_KERNEL_PREFIX "log_run");
  thread_attr_set_detached (&attr);
  int error = thread_create (&log_thread, &attr, log_run, NULL);

  if (error)
    panic ("log: unable to create thread");

  return (0);
}

INIT_OP_DEFINE (log_start,
                INIT_OP_DEP (log_setup, true),
                INIT_OP_DEP (thread_setup, true));

int
log_msg (unsigned int level, const char *format, ...)
{
  va_list ap;
  va_start (ap, format);

  int ret = log_vmsg (level, format, ap);
  va_end (ap);

  return (ret);
}

static int
log_puts (const struct log_record *record, int nr_chars)
{
  if ((unsigned int)nr_chars >= sizeof (record->msg))
    {
      log_msg (LOG_ERR, "log: message too large");
      goto out;
    }

  char *ptr = strchr (record->msg, '\n');

  if (ptr != NULL)
    {
      *ptr = '\0';
      nr_chars = ptr - record->msg;
    }

  assert (nr_chars >= 0);
  size_t size = offsetof (struct log_record, msg) + nr_chars + 1;

  cpu_flags_t flags;
  spinlock_lock_intr_save (&log_lock, &flags);

  int error = mbuf_push (&log_mbuf, record, size, true);

  if (error)
    log_nr_overruns++;

  thread_wakeup (log_thread);
  spinlock_unlock_intr_restore (&log_lock, flags);

out:
  return (nr_chars);
}

int
log_vmsg (unsigned int level, const char *format, va_list ap)
{
  assert (level < LOG_NR_LEVELS);
  struct log_record record = { .level = level };
  int nr_chars = vsnprintf (record.msg, sizeof (record.msg), format, ap);
  return (log_puts (&record, nr_chars));
}

struct bulletin*
log_get_bulletin (void)
{
  return (&log_bulletin);
}
