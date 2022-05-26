/*
 * Copyright (c) 2014 Richard Braun.
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

#ifndef TEST_TEST_H
#define TEST_TEST_H

#include <kern/init.h>
#include <kern/macros.h>

#define TEST_OK        0
#define TEST_SKIPPED   1
#define TEST_FAILED    2

void __init test_setup (void);

#define TEST_PREFIX   test_F_

#define TEST_ENTRY(name)   \
int CONCAT (TEST_PREFIX, name) (void)

#define TEST_ENTRY_INIT(name)   \
int __init test_F_##name (void)

#endif
