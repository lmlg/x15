#ifndef X15_FUTEX_H
#define X15_FUTEX_H

#define FUTEX_OP_WAIT      1
#define FUTEX_OP_WAKE      2
#define FUTEX_OP_REQUEUE   3

#define FUTEX_FLG_SHARED      (1u << 16)   // Futex may be shared across tasks.
#define FUTEX_FLG_TIMED       (1u << 17)   // Wait is time bound.
#define FUTEX_FLG_MUTATE      (1u << 18)   // Change contents before waking.
#define FUTEX_FLG_BROADCAST   (1u << 19)   // Wake all waiters.
#define FUTEX_FLG_ABSTIME     (1u << 20)   // Time passed is an absolute value.
#define FUTEX_FLG_PI          (1u << 21)   // Futex has PI semantics.

// Bits used in the futex word for PI and robust futexes.
#define FUTEX_WAITERS      (1u << 31)
#define FUTEX_OWNER_DIED   (1u << 30)
#define FUTEX_TID_MASK     (~(FUTEX_WAITERS | FUTEX_OWNER_DIED))

struct futex_robust_list
{
  int futex;
  int flags;
  unsigned long long next __attribute__ ((aligned (8)));
};

// Ensure binary layout is correct.

static_assert (sizeof (struct futex_robust_list) == 16,
               "invalid size for futex_robust_list");

static_assert (__builtin_offsetof (struct futex_robust_list, next) == 8,
               "invalid layout for futex_robust_list");

#endif
