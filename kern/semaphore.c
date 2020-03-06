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
 */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>

#include <kern/atomic.h>
#include <kern/futex.h>
#include <kern/semaphore.h>
#include <kern/semaphore_i.h>
#include <machine/cpu.h>

void
semaphore_init(struct semaphore *semaphore, uint16_t value, uint16_t max_value)
{
    assert(value <= max_value);

    semaphore->value = value;
    semaphore->max_value = max_value;
}

int
semaphore_trywait(struct semaphore *semaphore)
{
    struct semaphore tmp;
    int sv;

    for (;;) {
        tmp.both = atomic_load(&semaphore->both, ATOMIC_RELAXED);
        if (tmp.value == 0) {
            return EAGAIN;
        }

        sv = tmp.both;
        tmp.value--;

        if (atomic_cas(&semaphore->both, sv, tmp.both, ATOMIC_ACQUIRE) == sv) {
            return 0;
        }

        cpu_pause();
    }
}

void
semaphore_wait(struct semaphore *semaphore)
{
    struct semaphore tmp;
    int sv;

    for (;;) {
        tmp.both = atomic_load(&semaphore->both, ATOMIC_RELAXED);
        if (tmp.value == 0) {
            futex_wait(&semaphore->both, tmp.both, 0, 0);
            continue;
        }

        sv = tmp.both;
        tmp.value--;

        if (atomic_cas(&semaphore->both, sv, tmp.both, ATOMIC_ACQUIRE) == sv) {
            return;
        }

        cpu_pause();
    }
}

int
semaphore_timedwait(struct semaphore *semaphore, uint64_t ticks)
{
    struct semaphore tmp;
    int sv;

    for (;;) {
        tmp.both = atomic_load(&semaphore->both, ATOMIC_RELAXED);

        if (tmp.value != 0) {
            sv = tmp.both;
            tmp.value--;

            if (atomic_cas(&semaphore->both, sv, tmp.both,
                           ATOMIC_ACQUIRE) == sv) {
                return 0;
            }

            cpu_pause();
        } else if (futex_wait(&semaphore->both, tmp.both,
                              FUTEX_TIMED | FUTEX_ABS, ticks) == ETIMEDOUT) {
            return ETIMEDOUT;
        }
    }
}

int
semaphore_post(struct semaphore *semaphore)
{
    struct semaphore tmp;
    int sv;

    for (;;) {
        tmp.both = atomic_load(&semaphore->both, ATOMIC_RELAXED);

        if (tmp.value == tmp.max_value) {
            return EOVERFLOW;
        }

        sv = tmp.both;
        tmp.value++;

        if (atomic_cas(&semaphore->both, sv, tmp.both, ATOMIC_RELEASE) == sv) {
            futex_wake(&semaphore->both, 0, 0);
            return 0;
        }

        cpu_pause();
    }
}
