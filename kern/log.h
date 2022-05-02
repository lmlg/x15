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
 *
 *
 * System logging.
 */

#ifndef KERN_LOG_H
#define KERN_LOG_H

#include <stdarg.h>

#include <kern/init.h>

enum {
    LOG_EMERG,
    LOG_ALERT,
    LOG_CRIT,
    LOG_ERR,
    LOG_WARNING,
    LOG_NOTICE,
    LOG_INFO,
    LOG_DEBUG,
    LOG_NR_LEVELS,
};

/*
 * Type for function pointers that may be used as either a log function
 * or printf.
 *
 * One call to a log print function produces a single log line, with a
 * newline character.
 */
typedef int (*log_print_fn_t)(const char *format, ...)
    __attribute__((format(printf, 1, 2)));

/*
 * Generate a message and send it to the log thread.
 *
 * The arguments and return value are similar to printf(), with
 * these exceptions :
 *  - a level is associated to each log message
 *  - processing stops at the first terminating null byte or newline
 *    character, whichever occurs first
 *
 * This function may safely be called in interrupt context.
 */
int log_msg(unsigned int level, const char *format, ...)
    __attribute__((format(printf, 2, 3)));

int log_vmsg(unsigned int level, const char *format, va_list ap)
    __attribute__((format(printf, 2, 0)));

/*
 * Convenience wrappers.
 */

#define log_emerg(format, ...)   \
    log_msg(LOG_EMERG, (format), ##__VA_ARGS__)

#define log_alert(format, ...)   \
    log_msg(LOG_ALERT, (format), ##__VA_ARGS__)

#define log_crit(format, ...)   \
    log_msg(LOG_CRIT, (format), ##__VA_ARGS__)

#define log_err(format, ...)   \
    log_msg(LOG_ERR, (format), ##__VA_ARGS__)

#define log_warning(format, ...)   \
    log_msg(LOG_WARNING, (format), ##__VA_ARGS__)

#define log_notice(format, ...)   \
    log_msg(LOG_NOTICE, (format), ##__VA_ARGS__)

#define log_info(format, ...)   \
    log_msg(LOG_INFO, (format), ##__VA_ARGS__)

#define log_debug(format, ...)   \
    log_msg(LOG_DEBUG, (format), ##__VA_ARGS__)

/*
 * The bulletin returned by this function is used to notify the initial log
 * dump so that console output is well ordered.
 */
struct bulletin * log_get_bulletin(void);

/*
 * This init operation provides :
 *  - message logging
 *
 * The log thread isn't yet started and messages are merely stored in an
 * internal buffer.
 */
INIT_OP_DECLARE(log_setup);

#endif /* KERN_LOG_H */
