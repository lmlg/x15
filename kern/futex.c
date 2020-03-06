/*
 * Copyright (c) 2020 Richard Braun.
 * Copyright (c) 2020 Agustina Arzille.
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

#include <errno.h>

#include <kern/clock.h>
#include <kern/futex.h>
#include <kern/sleepq.h>

int
futex_wait(int *addr, int value, unsigned int flags, uint64_t ticks)
{
    struct sleepq *sleepq;
    int error;

    if (((uintptr_t)addr & (sizeof(*addr) - 1))) {
        return EINVAL;
    }

    sleepq = sleepq_lend(addr);

    if (*addr != value) {
        error = EAGAIN;
    } else if ((flags & FUTEX_TIMED) == 0) {
        sleepq_wait(sleepq, "futex");
        error = 0;
    } else {
        if ((flags & FUTEX_ABS) == 0) {
            ticks += clock_get_time() + 1;
        }

        error = sleepq_timedwait(sleepq, "futex", ticks);
    }

    sleepq_return(sleepq);
    return error;
}

int
futex_wake(int *addr, unsigned int flags, int value)
{
    struct sleepq *sleepq;
    int error;

    if (((uintptr_t)addr & (sizeof(*addr) - 1))) {
        return EINVAL;
    }

    error = 0;
    sleepq = sleepq_acquire(addr);

    if (flags & FUTEX_MODIFY) {
        *addr = value;
    }

    if (sleepq != NULL) {
        if (flags & FUTEX_BROADCAST) {
            sleepq_broadcast(sleepq);
        } else {
            sleepq_signal(sleepq);
        }

        sleepq_release(sleepq);
    }

    return error;
}

int
futex_requeue(int *src_addr, int *dst_addr,
              unsigned int flags, bool wake_one)
{
    if (((uintptr_t)src_addr | (uintptr_t)dst_addr) & (sizeof(*src_addr) - 1)) {
        return EINVAL;
    }

    return sleepq_move(src_addr, dst_addr, wake_one,
                       (flags & FUTEX_BROADCAST) != 0);
}
