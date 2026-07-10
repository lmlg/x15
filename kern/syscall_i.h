/*
 * Copyright (c) 2026 Agustina Arzille.
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
 * Helpers to define system calls.
 */

#ifndef KERN_SYSCALL_I_H
#define KERN_SYSCALL_I_H

#include <kern/macros.h>
#include <kern/types.h>

#ifdef __LP64__
#  define SYSCALL_LL(x)    (long long)(x)
#  define SYSCALL_ULL(x)   (unsigned long long)(x)
#else
  /*
   * On 32-bit platforms, syscalls cannot accept 64-bit arguments in a
   * single parameter.
   * We use these explicitly undefined functions when evaluating a 64-bit
   * argument to catch these errors at link time.
   */
  extern long long SYSCALL_LL (uintptr_t);
  extern unsigned long long SYSCALL_ULL (uintptr_t);
#endif

#define SYSCALL_ARG(fn, val)   \
  _Generic ((fn),   \
            void (*) (char): (char)(val),    \
            void (*) (unsigned char): (unsigned char)(val),   \
            void (*) (short): (short)(val),   \
            void (*) (unsigned short): (unsigned short)(val),   \
            void (*) (int): (int)(val),    \
            void (*) (unsigned int): (unsigned int)(val),   \
            void (*) (long): (long)(val),   \
            void (*) (unsigned long): (unsigned long)(val),   \
            void (*) (long long): SYSCALL_LL (val),   \
            void (*) (unsigned long long): SYSCALL_ULL (val),   \
            default: (void *)(val))

#define SYSCALL_HELPER_0()     (void)0
#define SYSCALL_HELPER_1(a1)   void (*__f1) (a1) = 0

#define SYSCALL_HELPER_2(a1, a2)   \
  SYSCALL_HELPER_1 (a1);   \
  void (*__f2) (a2) = 0

#define SYSCALL_HELPER_3(a1, a2, a3)   \
  SYSCALL_HELPER_2 (a1, a2);   \
  void (*__f3) (a3) = 0

#define SYSCALL_HELPER_4(a1, a2, a3, a4)   \
  SYSCALL_HELPER_3 (a1, a2, a3);   \
  void (*__f4) (a4) = 0

#define SYSCALL_HELPER_5(a1, a2, a3, a4, a5)   \
  SYSCALL_HELPER_4 (a1, a2, a3, a4);   \
  void (*__f5) (a5) = 0

#define SYSCALL_HELPER_6(a1, a2, a3, a4, a5, a6)   \
  SYSCALL_HELPER_5 (a1, a2, a3, a4, a5);   \
  void (*__f6) (a6) = 0

#define SYSCALL_ARGS_0
#define SYSCALL_ARGS_1   SYSCALL_ARG (__f1, __x1)
#define SYSCALL_ARGS_2   SYSCALL_ARGS_1, SYSCALL_ARG (__f2, __x2)
#define SYSCALL_ARGS_3   SYSCALL_ARGS_2, SYSCALL_ARG (__f3, __x3)
#define SYSCALL_ARGS_4   SYSCALL_ARGS_3, SYSCALL_ARG (__f4, __x4)
#define SYSCALL_ARGS_5   SYSCALL_ARGS_4, SYSCALL_ARG (__f5, __x5)
#define SYSCALL_ARGS_6   SYSCALL_ARGS_5, SYSCALL_ARG (__f6, __x6)

#define SYSCALL_NARGS_I(a, b, c, d, e, f, N, ...)   N
#define SYSCALL_NARGS(...)   \
  SYSCALL_NARGS_I (__VA_ARGS__, 6, 5, 4, 3, 2, 1, 0,)

#define SYSCALL_IMPL(storage, name, ...)   \
static ssize_t CONCAT (__sys_, name) (__VA_ARGS__);   \
storage ssize_t CONCAT (sys_, name) (uintptr_t __x1 __unused,   \
                                     uintptr_t __x2 __unused,   \
                                     uintptr_t __x3 __unused,   \
                                     uintptr_t __x4 __unused,   \
                                     uintptr_t __x5 __unused,   \
                                     uintptr_t __x6 __unused)   \
{   \
  CONCAT (SYSCALL_HELPER_, SYSCALL_NARGS (__VA_ARGS__)) (__VA_ARGS__);   \
  return (CONCAT (__sys_, name) (CONCAT (SYSCALL_ARGS_,   \
                                         SYSCALL_NARGS (__VA_ARGS__))));   \
}   \
static ssize_t CONCAT(__sys_, name) (__VA_ARGS__)

#define SYSCALL_STATIC(name, ...)   SYSCALL_IMPL (static, name, __VA_ARGS__)
#define SYSCALL(name, ...)          SYSCALL_IMPL (, name, __VA_ARGS__)

// Declare a syscall with external linkage.
#define SYSCALL_DECL(name)   \
  ssize_t sys_##name (uintptr_t, uintptr_t, uintptr_t,   \
                      uintptr_t, uintptr_t, uintptr_t)

#define SYSCALL_UARG_0
#define SYSCALL_UARG_1(a1)   (uintptr_t)(a1),
#define SYSCALL_UARG_2(a1, a2)   \
  SYSCALL_UARG_1 (a1) (uintptr_t)(a2),

#define SYSCALL_UARG_3(a1, a2, a3)   \
  SYSCALL_UARG_2 (a1, a2) (uintptr_t)(a3),

#define SYSCALL_UARG_4(a1, a2, a3, a4)   \
  SYSCALL_UARG_3 (a1, a2, a3) (uintptr_t)(a4),

#define SYSCALL_UARG_5(a1, a2, a3, a4, a5)   \
  SYSCALL_UARG_4 (a1, a2, a3, a4) (uintptr_t)(a5),

#define SYSCALL_UARG_6(a1, a2, a3, a4, a5, a6)   \
  SYSCALL_UARG_5 (a1, a2, a3, a4, a5) (uintptr_t)(a6),

// Enter a syscall from userspace.
#define SYSCALL_UENTER(sysno, ...)   \
  ({   \
     const uintptr_t args_[] =   \
       {   \
         CONCAT (SYSCALL_UARG_, SYSCALL_NARGS (__VA_ARGS__)) (__VA_ARGS__)   \
         0, 0, 0, 0, 0, 0   \
       };   \
     SYSCALL_ARCH_IMPL ((sysno), args_[0], args_[1], args_[2],   \
                        args_[3], args_[4], args_[5]);   \
   })

#endif
