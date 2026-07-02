#ifndef KERN_SYSCALL_I_H
#define KERN_SYSCALL_I_H

#ifdef __LP64__
#  define SYSCALL_LL(x)    (long long)(x)
#  define SYSCALL_ULL(x)   (unsigned long long)(x)
#else
  // Explicitly undefined so we get a link-time error.
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

#endif
