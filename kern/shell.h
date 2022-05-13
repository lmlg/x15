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
 *
 *
 * Minimalist shell for embedded systems.
 */

#ifndef KERN_SHELL_H
#define KERN_SHELL_H

#include <stdarg.h>
#include <stddef.h>

#include <kern/error.h>
#include <kern/init.h>
#include <kern/macros.h>

/*
 * Shell structure, statically allocatable.
 */
struct shell;

/*
 * Shell command structure.
 */
struct shell_cmd;

/*
 * Command container, shareable across multiple shell instances.
 */
struct shell_cmd_set;

/*
 * Type for command implementation callbacks.
 */
typedef void (*shell_fn_t)(struct shell *shell, int argc, char **argv);

#include <kern/shell_i.h>

#define SHELL_REGISTER_CMDS(cmds, cmd_set)                              \
MACRO_BEGIN                                                             \
    size_t i_;                                                          \
    int error_;                                                         \
                                                                        \
    for (i_ = 0; i_ < ARRAY_SIZE(cmds); i_++) {                         \
        error_ = shell_cmd_set_register(cmd_set, &(cmds)[i_]);          \
        error_check(error_, __func__);                                  \
    }                                                                   \
MACRO_END

/*
 * Static shell command initializers.
 */
#define SHELL_CMD_INITIALIZER(name, fn, usage, short_desc) \
    { NULL, NULL, name, fn, usage, short_desc, NULL }
#define SHELL_CMD_INITIALIZER2(name, fn, usage, short_desc, long_desc) \
    { NULL, NULL, name, fn, usage, short_desc, long_desc }

/*
 * Initialize a shell command structure.
 */
void shell_cmd_init(struct shell_cmd *cmd, const char *name,
                    shell_fn_t fn, const char *usage,
                    const char *short_desc, const char *long_desc);

/*
 * Initialize a command set.
 */
void shell_cmd_set_init(struct shell_cmd_set *cmd_set);

/*
 * Register a shell command.
 *
 * The command name must be unique. It must not include characters outside
 * the [a-zA-Z0-9-_] class.
 *
 * Commands may safely be registered while the command set is used.
 *
 * The command structure must persist in memory as long as the command set
 * is used.
 */
int shell_cmd_set_register(struct shell_cmd_set *cmd_set,
                           struct shell_cmd *cmd);

/*
 * Initialize a shell instance.
 *
 * On return, shell commands can be registered.
 */
void shell_init(struct shell *shell, struct shell_cmd_set *cmd_set,
                struct stream *stream);

/*
 * Obtain the command set associated with a shell.
 */
struct shell_cmd_set * shell_get_cmd_set(struct shell *shell);

/*
 * Printf-like functions specific to the given shell instance.
 */
void shell_printf(struct shell *shell, const char *format, ...)
    __attribute__((format(printf, 2, 3)));
void shell_vprintf(struct shell *shell, const char *format, va_list ap)
    __attribute__((format(printf, 2, 0)));

/*
 * This init operation provides :
 *  - main shell command registration
 */
INIT_OP_DECLARE(shell_setup);

struct shell_cmd_set * shell_get_main_cmd_set(void);

#endif /* KERN_SHELL_H */
