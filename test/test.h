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

#include <kern/fmt.h>
#include <kern/init.h>
#include <kern/macros.h>
#include <kern/panic.h>

#include <machine/page.h>

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

struct test_uctl
{
  uintptr_t arg1;
  uintptr_t arg2;
  int failure;
  int line;
};

#define test_uthread_stktop()   \
  ({   \
     uintptr_t top_ = (uintptr_t)__builtin_frame_address (0);   \
     (top_ & ~(PAGE_SIZE - 1)) + PAGE_SIZE;   \
   })

#define test_uthread_uctl()   \
  ({   \
     uintptr_t sp_ = test_uthread_stktop () - sizeof (struct test_uctl);   \
     (struct test_uctl *)sp_;   \
   })

#define test_uthread_arg()   \
  ({   \
     uintptr_t s_ = (uintptr_t)test_uthread_uctl () - sizeof (uintptr_t);   \
     *(void **)s_;   \
   })

#define test_uthread_err(a1, a2)   \
  do   \
    {   \
      _Auto uctl_ = test_uthread_uctl ();   \
      uctl_->failure = 1;   \
      uctl_->line = __LINE__;   \
      uctl_->arg1 = (uintptr_t)(a1);   \
      uctl_->arg2 = (uintptr_t)(a2);   \
      SYSCALL_UENTER (SYS_thread_exit, 0);   \
      __builtin_unreachable ();   \
    }   \
  while (0)

struct test_utask
{
  struct task *ktask;
  struct vm_page *data;
  char *data_cur;
  char *data_end;
  unsigned int num_thr;
};

struct test_uthread_attr
{
  unsigned int fnsize;
  struct test_utask *task;
  void (*prepare) (uintptr_t, void *);
};

struct test_uthread
{
  struct thread *kthr;
  struct test_utask *utask;
  struct vm_page *stack;
  struct vm_page *exec;
};

struct thread;

int test_util_create_thr (struct thread **out, void (*fn) (void *),
                          void *arg, const char *name);

// Create a userspace task.
int test_util_create_utask (struct test_utask *out, const char *name);

// Reserve room in the userspace VM map.
void* test_util_utask_reserve (struct test_utask *utask, size_t size);

// Create a userspace thread.
int test_util_create_uthr (struct test_uthread *out,
                           const struct test_uthread_attr *attr,
                           uintptr_t entry, void *arg);

// Join a userspace thread.
void test_util_uthr_join (struct test_uthread *uthr);

void test_thread_wait_state (struct thread *thr, uint32_t state);

// Test assertions.

#define test_fmt_get_spec(x)   \
  _Generic ((x),   \
            bool: "%d",   \
            char: "%c",   \
            unsigned char: "%d",   \
            short: "%d",   \
            unsigned short: "%d",   \
            int: "%d",   \
            unsigned int: "%u",   \
            long: "%ld",   \
            unsigned long: "%lu",   \
            long long: "%lld",   \
            unsigned long long: "%llu",   \
            const char*: "%s",   \
            default: "%p")

#define test_fmt_any(x, out)   \
  (fmt_sprintf ((out), test_fmt_get_spec (x), (x)), (out))

#define test_assert_op(x, y, op)   \
  ({   \
     _Auto left_ = (x);   \
     typeof (left_) right_ = (typeof (left_))(y);   \
     if (!(left_ op right_))   \
       {   \
         char buf1_[22], buf2_[22];   \
         panic ("assertion failed: %s %s %s at %s:%d",   \
                test_fmt_any (left_, buf1_),   \
                QUOTE (op),   \
                test_fmt_any (right_, buf2_),   \
                __FILE__, __LINE__);   \
       }   \
    })

#define test_assert_eq(x, y)   test_assert_op (x, y, ==)
#define test_assert_lt(x, y)   test_assert_op (x, y, <)
#define test_assert_le(x, y)   test_assert_op (x, y, <=)
#define test_assert_gt(x, y)   test_assert_op (x, y, >)
#define test_assert_ge(x, y)   test_assert_op (x, y, >=)
#define test_assert_ne(x, y)   test_assert_op (x, y, !=)

#define test_assert_zero(x)   test_assert_eq ((x), (typeof (x))0)

#define test_assert_nonnull(x)   \
  ({   \
      _Auto tmp_ = (x);   \
      if (! tmp_)   \
        panic ("assertion failed at %s:%d: " QUOTE (x) " is null",   \
               __FILE__, __LINE__);   \
  })   \

#define test_assert_streq(x, y)   \
  ({   \
      const char *x_ = (const char *)(x), *y_ = (const char *)(y);   \
      if (strcmp (x_, y_) != 0)   \
        panic ("assertion failed: %s is not equal to %s at %s:%d",   \
               x_, y_, __FILE__, __LINE__);   \
  })   \

#define test_assert_or(cond1, ...)   \
  ({   \
     const bool conds_[] = { (cond1), ##__VA_ARGS__ };   \
     bool works_ = false;   \
     for (size_t i_ = 0; i_ < ARRAY_SIZE (conds_) && !works_; ++i_)   \
       works_ = conds_[i_];   \
     if (!works_)   \
       panic ("assertion failed at %s:%d", __FILE__, __LINE__);   \
   })

#endif
