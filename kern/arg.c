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
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include <kern/arg.h>
#include <kern/init.h>
#include <kern/log.h>
#include <kern/macros.h>
#include <kern/panic.h>

/*
 * Internally, all space characters are turned into null bytes so that
 * values returned to callers directly point in the command line string,
 * with no need for dynamic allocation.
 */
static char arg_cmdline[ARG_CMDLINE_MAX_SIZE] __initdata;
static const char *arg_cmdline_end __initdata;

void __init
arg_set_cmdline (const char *cmdline)
{
  strlcpy (arg_cmdline, cmdline, sizeof (arg_cmdline));
}

static int __init
arg_setup (void)
{
  size_t length = strlen (arg_cmdline);
  for (size_t i = 0; i < length; i++)
    if (arg_cmdline[i] == ' ')
      arg_cmdline[i] = '\0';

  arg_cmdline_end = arg_cmdline + length;
  return (0);
}

INIT_OP_DEFINE (arg_setup);

void __init
arg_log_info (void)
{
  char cmdline[sizeof (arg_cmdline)];

  size_t i;
  for (i = 0; &arg_cmdline[i] < arg_cmdline_end; i++)
    cmdline[i] = arg_cmdline[i] ?: ' ';

  cmdline[i] = '\0';
  log_info ("arg: %s", cmdline);
}

static const char* __init
arg_walk (const char *s)
{
  if (s == NULL)
    s = arg_cmdline;
  else
    for ( ; ; ++s)
      if (s >= arg_cmdline_end)
        return (NULL);
      else if (*s == '\0')
        break;

  for ( ; ; ++s)
    {
      if (s >= arg_cmdline_end)
        return (NULL);
      else if (*s != '\0')
        return (s);
    }
}

static const char* __init
arg_find_name_end (const char *arg)
{
  const char *end = strchr (arg, '=');
  return (end ?: arg + strlen (arg));
}

static const char* __init
arg_find (const char *name)
{
  size_t name_length = strlen (name);
  assert (name_length);

  for (const char *arg = arg_walk (NULL); arg; arg = arg_walk (arg))
    {
      const char *arg_name_end = arg_find_name_end (arg);
      size_t arg_name_length = arg_name_end - arg;

      if (arg_name_length == name_length &&
          memcmp (arg, name, name_length) == 0)
        return (arg);
    }

  return (NULL);
}

bool __init
arg_present (const char *name)
{
  return (arg_find (name) != NULL);
}

const char* __init
arg_value (const char *name)
{
  const char *arg = arg_find (name);

  if (! arg)
    return (NULL);

  const char *value = strchr (arg, '=');
  return (value ? value + 1 : "");
}
