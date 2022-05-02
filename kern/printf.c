/*
 * Copyright (c) 2010-2019 Richard Braun.
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

#include <stdio.h>

#include <kern/console.h>
#include <kern/fmt.h>
#include <kern/init.h>
#include <kern/spinlock.h>
#include <machine/boot.h>
#include <machine/cpu.h>

struct printf_data {
    char buf[32];
    char *bp;
};

static void
printf_data_init(struct printf_data *data)
{
    data->bp = data->buf;
}

static void
printf_data_flush(struct printf_data *data)
{
    console_puts_nolock(data->buf, data->bp - data->buf);
    data->bp = data->buf;
}

static void
printf_putc(void *ptr, int ch)
{
    struct printf_data *data;

    data = ptr;
    if (data->bp == data->buf + sizeof(data->buf)) {
        printf_data_flush(data);
    }

    *data->bp++ = ch;
}

static int
vprintf_common(const char *format, va_list ap, bool newline)
{
    struct fmt_write_op op;
    struct printf_data data;
    int ret;
    unsigned long flags;

    printf_data_init(&data);
    op.putc = printf_putc;
    op.data = &data;

    console_lock(&flags);
    ret = fmt_vxprintf(&op, format, ap);

    if (newline) {
        op.putc(op.data, '\n');
    }

    if (data.bp != data.buf) {
        printf_data_flush(&data);
    }

    console_unlock(flags);
    return ret;
}

int
printf(const char *format, ...)
{
    va_list ap;
    int length;

    va_start(ap, format);
    length = vprintf(format, ap);
    va_end(ap);

    return length;
}

int
vprintf(const char *format, va_list ap)
{
    return vprintf_common(format, ap, false);
}

int
printf_ln(const char *format, ...)
{
    va_list ap;
    int length;

    va_start(ap, format);
    length = vprintf_common(format, ap, true);
    va_end(ap);

    return length;
}

int
vprintf_ln(const char *format, va_list ap)
{
    return vprintf_common(format, ap, true);
}

static int __init
printf_setup(void)
{
    return 0;
}

INIT_OP_DEFINE(printf_setup,
               INIT_OP_DEP(boot_bootstrap_console, true),
               INIT_OP_DEP(console_bootstrap, true),
               INIT_OP_DEP(spinlock_setup, true));
