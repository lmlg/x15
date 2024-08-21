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

#include <stdint.h>

#include <kern/init.h>
#include <kern/macros.h>

// Test exit status.
#define TEST_OK        0
#define TEST_SKIPPED   1
#define TEST_RUNNING   2
#define TEST_FAILED    3

void __init test_setup (void);

/*
 * Tests can be classified in 2 types: inline and deferred.
 * Inline tests are run as they are discovered, whereas deferred tests create a
 * detached thread that runs once the needed subsystems are up.
 * In order for tests to be inline, they must only use the most basic of the
 * functionalities that the kernel provides, since test discovery is run very
 * early (Before application processors are up). 
 */

#define TEST_PREFIX        test_F
#define TEST_INLINE_CHAR   I

// Convert 'name' to 'test_FI_name'.
#define TEST_INLINE(name)   \
  int __init CONCAT (TEST_PREFIX,   \
                     CONCAT (TEST_INLINE_CHAR, CONCAT (_, name))) (void)

// Convert 'name' to 'test_F_name'.
#define TEST_DEFERRED(name)   \
  int __init CONCAT (TEST_PREFIX, CONCAT (_, name)) (void)

// Utilities for the test module.

struct thread;

int test_util_create_thr (struct thread **out, void (*fn) (void *),
                          void *arg, const char *name);

void test_thread_wait_state (struct thread *thr, uint32_t state);

#endif
