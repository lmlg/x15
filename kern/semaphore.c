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
    semaphore->values = ((uint32_t)max_value << 16) + value;
}

int
semaphore_trywait(struct semaphore *semaphore)
{
    uint32_t values;

    for (;;) {
        values = atomic_load(&semaphore->values, ATOMIC_RELAXED);
        if ((values & 0xffff) == 0) {
            return EAGAIN;
        } else if (atomic_cas(&semaphore->values, values, values - 1,
                              ATOMIC_ACQUIRE) == values) {
            return 0;
        }

        cpu_pause();
    }
}

void
semaphore_wait(struct semaphore *semaphore)
{
    uint32_t values;

    for (;;) {
        values = atomic_load(&semaphore->values, ATOMIC_RELAXED);
        if ((values & 0xffff) == 0) {
            futex_wait(&semaphore->values, values, 0, 0);
            continue;
        } else if (atomic_cas(&semaphore->values, values, values - 1,
                              ATOMIC_ACQUIRE) == values) {
            return;
        }

        cpu_pause();
    }
}

int
semaphore_timedwait(struct semaphore *semaphore, uint64_t ticks)
{
    uint32_t values;

    for (;;) {
        values = atomic_load(&semaphore->values, ATOMIC_RELAXED);
        if ((values & 0xffff) != 0) {
            if (atomic_cas(&semaphore->values, values, values - 1,
                           ATOMIC_ACQUIRE) == values) {
                return 0;
            }

            cpu_pause();
        } else if (futex_wait(&semaphore->values, values,
                              FUTEX_TIMED | FUTEX_ABS, ticks) == ETIMEDOUT) {
            return ETIMEDOUT;
        }
    }
}

int
semaphore_post(struct semaphore *semaphore)
{
    uint32_t values;

    for (;;) {
        values = atomic_load(&semaphore->values, ATOMIC_RELAXED);
        if ((values & 0xffff) == (values >> 16)) {
            return EOVERFLOW;
        } else if (atomic_cas(&semaphore->values, values, values + 1,
                              ATOMIC_RELEASE) == values) {
            futex_wake(&semaphore->values, 0, 0);
            return 0;
        }

        cpu_pause();
    }
}
