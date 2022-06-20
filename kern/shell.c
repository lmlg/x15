/*
 * Copyright (c) 2015-2018 Richard Braun.
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
 * Upstream site with license notes :
 * http://git.sceen.net/rbraun/librbraun.git/
 */

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <kern/bulletin.h>
#include <kern/hash.h>
#include <kern/init.h>
#include <kern/log.h>
#include <kern/macros.h>
#include <kern/mutex.h>
#include <kern/printf.h>
#include <kern/shell.h>
#include <kern/thread.h>

#define SHELL_COMPLETION_MATCH_FMT              "-16s"
#define SHELL_COMPLETION_NR_MATCHES_PER_LINE    4

/*
 * Escape sequence states.
 *
 * Here is an incomplete description of escape sequences :
 * http://en.wikipedia.org/wiki/ANSI_escape_code
 *
 * These values must be different from 0.
 */
#define SHELL_ESC_STATE_START   1
#define SHELL_ESC_STATE_CSI     2

typedef void (*shell_esc_seq_fn) (struct shell *);

struct shell_esc_seq
{
  const char *str;
  shell_esc_seq_fn fn;
};

#define SHELL_SEPARATOR ' '

/*
 * Commonly used backspace control characters.
 *
 * XXX Adjust for your needs.
 */
#define SHELL_ERASE_BS    '\b'
#define SHELL_ERASE_DEL   '\x7f'

static struct bulletin_sub shell_log_bulletin_sub;

static const char*
shell_find_word (const char *str)
{
  for ( ; ; ++str)
    if (!*str || *str != SHELL_SEPARATOR)
      return (str);
}

void
shell_cmd_init (struct shell_cmd *cmd, const char *name,
                shell_fn_t fn, const char *usage,
                const char *short_desc, const char *long_desc)
{
  cmd->ht_next = NULL;
  cmd->ls_next = NULL;
  cmd->name = name;
  cmd->fn = fn;
  cmd->usage = usage;
  cmd->short_desc = short_desc;
  cmd->long_desc = long_desc;
}

static const char*
shell_cmd_name (const struct shell_cmd *cmd)
{
  return (cmd->name);
}

static int
shell_cmd_check_char (char c)
{
  if ((c >= 'a' && c <= 'z') ||
      (c >= 'A' && c <= 'Z') ||
      (c >= '0' && c <= '9') ||
      c == '-' || c == '_')
    return (0);

  return (EINVAL);
}

static int
shell_cmd_check (const struct shell_cmd *cmd)
{
  size_t len = strlen (cmd->name);
  if (! len)
    return (EINVAL);

  for (size_t i = 0; i < len; i++)
    {
      int error = shell_cmd_check_char (cmd->name[i]);
      if (error)
        return (error);
    }

  return (0);
}

static const char*
shell_line_str (const struct shell_line *line)
{
  return (line->str);
}

static size_t
shell_line_size (const struct shell_line *line)
{
  return (line->size);
}

static void
shell_line_reset (struct shell_line *line)
{
  line->str[0] = '\0';
  line->size = 0;
}

static void
shell_line_copy (struct shell_line *dest, const struct shell_line *src)
{
  strcpy (dest->str, src->str);
  dest->size = src->size;
}

static int
shell_line_cmp (const struct shell_line *a, const struct shell_line *b)
{
  return (strcmp (a->str, b->str));
}

static int
shell_line_insert (struct shell_line *line, size_t index, char c)
{
  if (index > line->size)
    return (EINVAL);
  else if (line->size + 1 == sizeof (line->str))
    return (ENOMEM);

  size_t remaining_chars = line->size - index;
  if (remaining_chars)
    memmove (&line->str[index + 1], &line->str[index], remaining_chars);

  line->str[index] = c;
  line->str[++line->size] = '\0';
  return (0);
}

static int
shell_line_erase (struct shell_line *line, size_t index)
{
  if (index >= line->size)
    return (EINVAL);

  size_t remaining_chars = line->size - index - 1;
  if (remaining_chars)
    memmove (&line->str[index], &line->str[index + 1], remaining_chars);

  line->str[--line->size] = '\0';
  return (0);
}

static struct shell_line*
shell_history_get (struct shell_history *history, size_t index)
{
  return (&history->lines[index % ARRAY_SIZE (history->lines)]);
}

static void
shell_history_init (struct shell_history *history)
{
  for (size_t i = 0; i < ARRAY_SIZE (history->lines); i++)
    shell_line_reset (shell_history_get (history, i));

  history->newest = 0;
  history->oldest = 0;
  history->index = 0;
}

static struct shell_line*
shell_history_get_newest (struct shell_history *history)
{
  return (shell_history_get (history, history->newest));
}

static struct shell_line *
shell_history_get_index (struct shell_history *history)
{
  return (shell_history_get (history, history->index));
}

static void
shell_history_reset_index (struct shell_history *history)
{
  history->index = history->newest;
}

static int
shell_history_same_newest (struct shell_history *history)
{
  return (history->newest != history->oldest &&
          shell_line_cmp (shell_history_get_newest (history),
                          shell_history_get (history, history->newest - 1))
             == 0);
}

static void
shell_history_push (struct shell_history *history)
{
  if (shell_line_size (shell_history_get_newest (history)) == 0 ||
      shell_history_same_newest (history))
    {
      shell_history_reset_index (history);
      return;
    }

  ++history->newest;
  shell_history_reset_index (history);

  // Mind integer overflows.
  if (history->newest - history->oldest >= ARRAY_SIZE (history->lines))
    history->oldest = history->newest - ARRAY_SIZE (history->lines) + 1;
}

static void
shell_history_back (struct shell_history *history)
{
  if (history->index == history->oldest)
    return;

  --history->index;
  shell_line_copy (shell_history_get_newest (history),
                   shell_history_get_index (history));
}

static void
shell_history_forward (struct shell_history *history)
{
  if (history->index == history->newest)
    return;
  else if (++history->index == history->newest)
    shell_line_reset (shell_history_get_newest (history));
  else
    shell_line_copy (shell_history_get_newest (history),
                     shell_history_get_index (history));
}

static void
shell_history_print (struct shell_history *history, struct shell *shell)
{
  // Mind integer overflows.
  for (size_t i = history->oldest; i != history->newest; i++)
    {
      _Auto line = shell_history_get (history, i);
      shell_printf (shell, "%6lu  %s\n",
                    (unsigned long) (i - history->oldest),
                    shell_line_str (line));
    }
}

static void
shell_cmd_set_lock (struct shell_cmd_set *cmd_set)
{
  mutex_lock (&cmd_set->lock);
}

static void
shell_cmd_set_unlock (struct shell_cmd_set *cmd_set)
{
  mutex_unlock (&cmd_set->lock);
}

static struct shell_bucket*
shell_cmd_set_get_bucket (struct shell_cmd_set *cmd_set, const char *name)
{
  size_t index = hash_str (name, SHELL_HTABLE_BITS);
  assert (index < ARRAY_SIZE (cmd_set->htable));
  return (&cmd_set->htable[index]);
}

static const struct shell_cmd*
shell_cmd_set_lookup (struct shell_cmd_set *cmd_set, const char *name)
{
  shell_cmd_set_lock (cmd_set);

  const _Auto bucket = shell_cmd_set_get_bucket (cmd_set, name);
  _Auto cmd = bucket->cmd;

  for (; cmd != NULL; cmd = cmd->ht_next)
    if (strcmp (cmd->name, name) == 0)
      break;

  shell_cmd_set_unlock (cmd_set);
  return (cmd);
}

/*
 * Look up the first command that matches a given string.
 *
 * The input string is defined by the given string pointer and size.
 *
 * The global lock must be acquired before calling this function.
 */
static const struct shell_cmd*
shell_cmd_set_match (const struct shell_cmd_set *cmd_set, const char *str,
                     size_t size)
{
  const struct shell_cmd *cmd = cmd_set->cmd_list;
  while (cmd)
    {
      if (strncmp (cmd->name, str, size) == 0)
        return (cmd);

      cmd = cmd->ls_next;
    }

  return (NULL);
}

/*
 * Attempt command auto-completion.
 *
 * The given string is the beginning of a command, or the empty string.
 * The sizep parameter initially points to the size of the given string.
 * If the string matches any registered command, the cmdp pointer is
 * updated to point to the first matching command in the sorted list of
 * commands, and sizep is updated to the number of characters in the
 * command name that are common in subsequent commands. The command
 * pointer and the returned size can be used to print a list of commands
 * eligible for completion.
 *
 * If there is a single match for the given string, return 0. If there
 * are more than one match, return EAGAIN. If there is no match,
 * return EINVAL.
 */
static int
shell_cmd_set_complete (struct shell_cmd_set *cmd_set, const char *str,
                        size_t *sizep, const struct shell_cmd **cmdp)
{
  size_t size = *sizep;

  /*
   * Start with looking up a command that matches the given argument.
   * If there is no match, return an error.
   */
  const _Auto cmd = shell_cmd_set_match (cmd_set, str, size);
  if (! cmd)
    return (EINVAL);

  *cmdp = cmd;

  /*
   * If at least one command matches, try to complete it.
   * There can be two cases :
   * 1/ There is one and only one match, which is directly returned.
   * 2/ There are several matches, in which case the common length is
   *    computed.
   */
  const struct shell_cmd *next = cmd->ls_next;
  if (!next || strncmp (cmd->name, next->name, size))
    {
      *sizep = strlen (cmd->name);
      return (0);
    }

  /*
   * When computing the common length, all the commands that can match
   * must be evaluated. Considering the current command is the first
   * that can match, the only other variable missing is the last
   * command that can match.
   */
  for (; next->ls_next; next = next->ls_next)
    if (strncmp (cmd->name, next->ls_next->name, size))
      break;

  if (! size)
    size = 1;

  while (cmd->name[size - 1] != '\0' &&
      cmd->name[size - 1] == next->name[size - 1])
    size++;

  *sizep = --size;
  return (EAGAIN);
}

struct shell_cmd_set*
shell_get_cmd_set (struct shell *shell)
{
  return (shell->cmd_set);
}

static struct shell_history*
shell_get_history (struct shell *shell)
{
  return (&shell->history);
}

static void
shell_cb_help (struct shell *shell, int argc, char *argv[])
{
  _Auto cmd_set = shell_get_cmd_set (shell);

  if (argc > 2)
    {
      argc = 2;
      argv[1] = "help";
    }

  if (argc == 2)
    {
      _Auto cmd = shell_cmd_set_lookup (cmd_set, argv[1]);
      if (! cmd)
        {
          shell_printf (shell, "shell: help: %s: command not found\n",
                        argv[1]);
          return;
        }

      shell_printf (shell, "usage: %s\n%s\n", cmd->usage, cmd->short_desc);

      if (cmd->long_desc)
        shell_printf (shell, "\n%s\n", cmd->long_desc);

      return;
    }

  shell_cmd_set_lock (cmd_set);

  for (_Auto cmd = cmd_set->cmd_list; cmd; cmd = cmd->ls_next)
    shell_printf (shell, "%19s  %s\n", cmd->name, cmd->short_desc);

  shell_cmd_set_unlock (cmd_set);
}

static void
shell_cb_history (struct shell *shell, int argc __unused, char **argv __unused)
{
  shell_history_print (shell_get_history (shell), shell);
}

static struct shell_cmd shell_default_cmds[] =
{
  SHELL_CMD_INITIALIZER ("help", shell_cb_help,
                         "help [command]",
                         "obtain help about shell commands"),
  SHELL_CMD_INITIALIZER ("history", shell_cb_history,
                         "history",
                         "display history list"),
};

void
shell_cmd_set_init (struct shell_cmd_set *cmd_set)
{
  mutex_init (&cmd_set->lock);
  memset (cmd_set->htable, 0, sizeof (cmd_set->htable));
  cmd_set->cmd_list = NULL;
  SHELL_REGISTER_CMDS (shell_default_cmds, cmd_set);
}

static int
shell_cmd_set_add_htable (struct shell_cmd_set *cmd_set, struct shell_cmd *cmd)
{
  _Auto bucket = shell_cmd_set_get_bucket (cmd_set, cmd->name);
  _Auto tmp = bucket->cmd;

  if (! tmp)
    {
      bucket->cmd = cmd;
      return (0);
    }

  for ( ; ; tmp = tmp->ht_next)
    if (strcmp (cmd->name, tmp->name) == 0)
      return (EEXIST);
    else if (!tmp->ht_next)
      break;

  tmp->ht_next = cmd;
  return (0);
}

static void
shell_cmd_set_add_list (struct shell_cmd_set *cmd_set, struct shell_cmd *cmd)
{
  _Auto prev = cmd_set->cmd_list;

  if (!prev || strcmp (cmd->name, prev->name) < 0)
    {
      cmd_set->cmd_list = cmd;
      cmd->ls_next = prev;
      return;
    }

  struct shell_cmd *next;
  while (1)
    {
      next = prev->ls_next;

      if (!next || strcmp (cmd->name, next->name) < 0)
        break;

      prev = next;
    }

  prev->ls_next = cmd;
  cmd->ls_next = next;
}

static int
shell_cmd_set_add (struct shell_cmd_set *cmd_set, struct shell_cmd *cmd)
{
  int error = shell_cmd_set_add_htable (cmd_set, cmd);
  if (error)
    return (error);

  shell_cmd_set_add_list (cmd_set, cmd);
  return (0);
}

int
shell_cmd_set_register (struct shell_cmd_set *cmd_set, struct shell_cmd *cmd)
{
  int error = shell_cmd_check (cmd);
  if (error)
    return (error);

  shell_cmd_set_lock (cmd_set);
  error = shell_cmd_set_add (cmd_set, cmd);
  shell_cmd_set_unlock (cmd_set);

  return (error);
}

void
shell_init (struct shell *shell, struct shell_cmd_set *cmd_set,
            struct stream *stream)
{
  shell->cmd_set = cmd_set;
  shell->stream = stream;
  shell_history_init (&shell->history);
  shell->esc_seq_index = 0;
}

static void
shell_prompt (struct shell *shell)
{
  shell_printf (shell, "shell> ");
}

static void
shell_reset (struct shell *shell)
{
  shell_line_reset (shell_history_get_newest (&shell->history));
  shell->cursor = 0;
  shell_prompt (shell);
}

static void
shell_erase (struct shell *shell)
{
  _Auto current_line = shell_history_get_newest (&shell->history);
  size_t remaining_chars = shell_line_size (current_line);

  while (shell->cursor != remaining_chars)
    {
      shell_printf (shell, " ");
      shell->cursor++;
    }

  while (remaining_chars != 0)
    {
      shell_printf (shell, "\b \b");
      remaining_chars--;
    }

  shell->cursor = 0;
}

static void
shell_restore (struct shell *shell)
{
  _Auto current_line = shell_history_get_newest (&shell->history);
  shell_printf (shell, "%s", shell_line_str (current_line));
  shell->cursor = shell_line_size (current_line);
}

static int
shell_is_ctrl_char (char c)
{
  return (c < ' ' || c >= 0x7f);
}

static void
shell_process_left (struct shell *shell)
{
  if (!shell->cursor)
    return;

  --shell->cursor;
  shell_printf (shell, "\e[1D");
}

static int
shell_process_right (struct shell *shell)
{
  size_t size = shell_line_size (shell_history_get_newest (&shell->history));
  if (shell->cursor >= size)
    return (EAGAIN);

  ++shell->cursor;
  shell_printf (shell, "\e[1C");
  return 0;
}

static void
shell_process_up (struct shell *shell)
{
  shell_erase (shell);
  shell_history_back (&shell->history);
  shell_restore (shell);
}

static void
shell_process_down (struct shell *shell)
{
  shell_erase (shell);
  shell_history_forward (&shell->history);
  shell_restore (shell);
}

static void
shell_process_backspace (struct shell *shell)
{
  _Auto current_line = shell_history_get_newest (&shell->history);
  int error = shell_line_erase (current_line, shell->cursor - 1);

  if (error)
    return;

  --shell->cursor;
  shell_printf (shell, "\b%s ", shell_line_str (current_line) + shell->cursor);

  size_t remaining_chars = shell_line_size (current_line) - shell->cursor + 1;
  for (; remaining_chars; --remaining_chars)
    shell_printf (shell, "\b");
}

static int
shell_process_raw_char (struct shell *shell, char c)
{
  _Auto current_line = shell_history_get_newest (&shell->history);
  int error = shell_line_insert (current_line, shell->cursor, c);

  if (error)
    {
      shell_printf (shell, "\nshell: line too long\n");
      return (error);
    }
  else if (++shell->cursor == shell_line_size (current_line))
    {
      shell_printf (shell, "%c", c);
      return (0);
    }

  /*
   * This assumes that the backspace character only moves the cursor
   * without erasing characters.
   */
  shell_printf (shell, "%s",
                shell_line_str (current_line) + shell->cursor - 1);

  size_t remaining_chars = shell_line_size (current_line) - shell->cursor;
  for (; remaining_chars; --remaining_chars)
    shell_printf (shell, "\b");

  return (0);
}

/*
 * Print a list of commands eligible for completion, starting at the
 * given command. Other eligible commands share the same prefix, as
 * defined by the size argument.
 *
 * The global lock must be acquired before calling this function.
 */
static void
shell_print_cmd_matches (struct shell *shell, const struct shell_cmd *cmd,
                         size_t size)
{
  shell_printf (shell, "\n");

  const struct shell_cmd *tmp;
  size_t i;
  for (tmp = cmd, i = 1; tmp != NULL; tmp = tmp->ls_next, i++)
    {
      if (strncmp (cmd->name, tmp->name, size) != 0)
        break;

      shell_printf (shell, "%" SHELL_COMPLETION_MATCH_FMT, tmp->name);

      if ((i % SHELL_COMPLETION_NR_MATCHES_PER_LINE) == 0)
        shell_printf (shell, "\n");
    }

  if ((i % SHELL_COMPLETION_NR_MATCHES_PER_LINE) != 1)
    shell_printf (shell, "\n");
}

static int
shell_process_tabulation (struct shell *shell)
{
  const struct shell_cmd *cmd = NULL; /* GCC */

  _Auto cmd_set = shell->cmd_set;
  shell_cmd_set_lock (cmd_set);

  _Auto str = shell_line_str (shell_history_get_newest (&shell->history));
  const char *word = shell_find_word (str);
  size_t size = shell->cursor - (word - str),
         cmd_cursor = shell->cursor - size;

  int error = shell_cmd_set_complete (cmd_set, word, &size, &cmd);

  if (error && error != EAGAIN)
    {
      error = 0;
      goto out;
    }
  else if (error == EAGAIN)
    {
      size_t cursor = shell->cursor;
      shell_print_cmd_matches (shell, cmd, size);
      shell_prompt (shell);
      shell_restore (shell);

      // Keep existing arguments as they are.
      while (shell->cursor != cursor)
        shell_process_left (shell);
    }

  const char *name = shell_cmd_name (cmd);

  while (shell->cursor != cmd_cursor)
    shell_process_backspace (shell);

  for (size_t i = 0; i < size; i++)
    {
      error = shell_process_raw_char (shell, name[i]);

      if (error)
        goto out;
    }

  error = 0;

out:
  shell_cmd_set_unlock (cmd_set);
  return (error);
}

static void
shell_esc_seq_up (struct shell *shell)
{
  shell_process_up (shell);
}

static void
shell_esc_seq_down (struct shell *shell)
{
  shell_process_down (shell);
}

static void
shell_esc_seq_next (struct shell *shell)
{
  shell_process_right (shell);
}

static void
shell_esc_seq_prev (struct shell *shell)
{
  shell_process_left (shell);
}

static void
shell_esc_seq_home (struct shell *shell)
{
  while (shell->cursor)
    shell_process_left (shell);
}

static void
shell_esc_seq_del (struct shell *shell)
{
  if (shell_process_right (shell) == 0)
    shell_process_backspace (shell);
}

static void
shell_esc_seq_end (struct shell *shell)
{
  size_t size = shell_line_size (shell_history_get_newest (&shell->history));
  while (shell->cursor < size)
    shell_process_right (shell);
}

static const struct shell_esc_seq shell_esc_seqs[] =
{
  {  "A", shell_esc_seq_up    },
  {  "B", shell_esc_seq_down  },
  {  "C", shell_esc_seq_next  },
  {  "D", shell_esc_seq_prev  },
  {  "H", shell_esc_seq_home  },
  { "1~", shell_esc_seq_home  },
  { "3~", shell_esc_seq_del   },
  {  "F", shell_esc_seq_end   },
  { "4~", shell_esc_seq_end   },
};

static const struct shell_esc_seq*
shell_esc_seq_lookup (const char *str)
{
  for (size_t i = 0; i < ARRAY_SIZE (shell_esc_seqs); i++)
    if (strcmp (shell_esc_seqs[i].str, str) == 0)
      return (&shell_esc_seqs[i]);

  return (NULL);
}

/*
 * Process a single escape sequence character.
 *
 * Return the next escape state or 0 if the sequence is complete.
 */
static int
shell_process_esc_sequence (struct shell *shell, char c)
{
  if (shell->esc_seq_index >= (ARRAY_SIZE (shell->esc_seq) - 1))
    {
      shell_printf (shell, "shell: escape sequence too long\n");
      goto reset;
    }

  shell->esc_seq[shell->esc_seq_index++] = c;
  shell->esc_seq[shell->esc_seq_index] = '\0';

  if (c >= '@' && c <= '~')
    {
      _Auto seq = shell_esc_seq_lookup (shell->esc_seq);
      if (seq)
        seq->fn (shell);

      goto reset;
    }

  return (SHELL_ESC_STATE_CSI);

reset:
  shell->esc_seq_index = 0;
  return (0);
}

static int
shell_process_args (struct shell *shell)
{
  snprintf (shell->tmp_line, sizeof (shell->tmp_line), "%s",
            shell_line_str (shell_history_get_newest (&shell->history)));

  char c, prev;
  size_t i;
  int j;

  for (i = 0, j = 0, prev = SHELL_SEPARATOR;
       (c = shell->tmp_line[i]) != '\0';
       i++, prev = c)
    {
      if (c == SHELL_SEPARATOR)
        {
          if (prev != SHELL_SEPARATOR)
            shell->tmp_line[i] = '\0';
        }
      else
        {
          if (prev == SHELL_SEPARATOR)
            {
              shell->argv[j] = &shell->tmp_line[i];
              j++;

              if (j == ARRAY_SIZE (shell->argv))
                {
                  shell_printf (shell, "shell: too many arguments\n");
                  return (EINVAL);
                }

              shell->argv[j] = NULL;
            }
        }
    }

  shell->argc = j;
  return (0);
}

static void
shell_process_line (struct shell *shell)
{
  const struct shell_cmd *cmd = NULL;
  int error = shell_process_args (shell);

  if (error || shell->argc == 0)
    goto out;

  cmd = shell_cmd_set_lookup (shell->cmd_set, shell->argv[0]);

  if (! cmd)
    {
      shell_printf (shell, "shell: %s: command not found\n", shell->argv[0]);
      goto out;
    }

out:
  shell_history_push (&shell->history);

  if (cmd)
    cmd->fn (shell, shell->argc, shell->argv);
}

/*
 * Process a single control character.
 *
 * Return an error if the caller should reset the current line state.
 */
static int
shell_process_ctrl_char (struct shell *shell, char c)
{
  switch (c)
    {
      case SHELL_ERASE_BS:
      case SHELL_ERASE_DEL:
        shell_process_backspace (shell);
        break;
      case '\t':
        return (shell_process_tabulation (shell));
      case '\n':
      case '\r':
        shell_printf (shell, "\n");
        shell_process_line (shell);
        return (EAGAIN);
      default:
        return (0);
    }

  return (0);
}

static void
shell_run (struct shell *shell)
{
  while (1)
    {
      shell_reset (shell);
      int error, escape = 0;

      while (1)
        {
          int c = stream_getc (shell->stream);

          if (escape)
            {
              switch (escape)
                {
                case SHELL_ESC_STATE_START:
                  // XXX CSI and SS3 sequence processing is the same.
                  if (c == '[' || c == 'O')
                    escape = SHELL_ESC_STATE_CSI;
                  else
                    escape = 0;

                  break;
                case SHELL_ESC_STATE_CSI:
                  escape = shell_process_esc_sequence (shell, c);
                  break;
                default:
                  escape = 0;
                }

              error = 0;
            }
          else if (shell_is_ctrl_char (c))
            {
              if (c == '\e')
                {
                  escape = SHELL_ESC_STATE_START;
                  error = 0;
                }
              else
                {
                  error = shell_process_ctrl_char (shell, c);
                  if (error)
                    break;
                }
            }
          else
            error = shell_process_raw_char (shell, c);

          if (error)
            break;
        }
    }
}

void
shell_printf (struct shell *shell, const char *format, ...)
{
  va_list ap;
  va_start (ap, format);
  shell_vprintf (shell, format, ap);
  va_end (ap);
}

void
shell_vprintf (struct shell *shell, const char *format, va_list ap)
{
  fmt_vxprintf (shell->stream, format, ap);
}

static struct shell_cmd_set shell_main_cmd_set;
static struct shell shell_main;

static void
shell_main_run (void *arg)
{
  shell_run (arg);
}

static void
shell_start (uintptr_t value __unused, void *arg __unused)
{
  struct thread_attr attr;
  thread_attr_init (&attr, THREAD_KERNEL_PREFIX "shell");
  thread_attr_set_detached (&attr);

  struct thread *thread;
  int error = thread_create (&thread, &attr, shell_main_run, &shell_main);
  error_check (error, "thread_create");
}

static int __init
shell_setup (void)
{
  shell_cmd_set_init (&shell_main_cmd_set);
  shell_init (&shell_main, &shell_main_cmd_set, console_stream);
  bulletin_subscribe (log_get_bulletin (), &shell_log_bulletin_sub,
                      shell_start, NULL);

  return (0);
}

INIT_OP_DEFINE (shell_setup,
                INIT_OP_DEP (log_setup, true),
                INIT_OP_DEP (mutex_setup, true),
                INIT_OP_DEP (printf_setup, true),
                INIT_OP_DEP (stream_setup, true));

struct shell_cmd_set* __init
shell_get_main_cmd_set (void)
{
  return (&shell_main_cmd_set);
}
