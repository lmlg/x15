/*
 * Copyright (c) 2022 Agustina Arzille.
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
 */

#include <assert.h>
#include <string.h>
#include <kern/error.h>
#include <kern/fmt.h>
#include <kern/init.h>
#include <kern/log.h>
#include <test/test.h>

static void
test_printf_putc(void *data, int ch)
{
    char **ptr;

    ptr = data;
    **ptr = ch < 'A' || ch > 'Z' ? ch : ((ch - 'A') + 'a');
    (*ptr)++;
}

static void
test_sscanf(void)
{
    int rv, x1, x2;
    char c1, c2;

    rv = fmt_sscanf("123 qx -45", "%d %c%c %d", &x1, &c1, &c2, &x2);
    assert(rv == 4);
    assert(x1 == 123);
    assert(c1 == 'q');
    assert(c2 == 'x');
    assert(x2 == -45);
}

void __init
test_setup(void)
{
    char buf[32], *p;
    struct fmt_write_op write_op;
    int rv;

    rv = fmt_sprintf(buf, "hello %d %s", -4, "???");
    assert(rv == 12);
    rv = strcmp(buf, "hello -4 ???");
    assert(rv == 0);

    rv = fmt_snprintf(buf, 4, "abc%d", 33);
    assert(rv == 5);
    buf[rv - 1] = '\0';
    rv = strcmp(buf, "abc3");
    assert(rv == 0);

    p = buf;
    write_op.data = &p;
    write_op.putc = test_printf_putc;

    rv = fmt_xprintf(&write_op, "HELLO %d", -1);
    assert(rv > 0);
    buf[rv] = '\0';
    assert(strcmp(buf, "hello -1") == 0);

    test_sscanf();

    log_info("fmt test done");
}
