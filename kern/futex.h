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
 *
 * Fast wait queues for userspace and kernel.
 */

#ifndef KERN_FUTEX_H
#define KERN_FUTEX_H

#include <stdint.h>

#define FUTEX_TIMED       0x01
#define FUTEX_ABS         0x02
#define FUTEX_BROADCAST   0x04
#define FUTEX_MODIFY      0x08

/*
 * Test that the futex address still contains the expected value, and if so,
 * sleep until another thread calls 'futex_wake' on the same address, or
 * a timeout elapses (if FUTEX_TIMED is set on the flags).
 *
 * If the futex address does not contain the expected value, the call returns
 * immediately with EAGAIN.
 */
int futex_wait(void *addr, int value, unsigned int flags, uint64_t ticks);

/*
 * Wake one or all waiters that are sleeping on a futex address (depending on
 * whether the FUTEX_BROADCAST flag is set or not). If FUTEX_MODIFY is in the
 * flags, set the content of the address to the value before waking up threads.
 */
int futex_wake(void *addr, unsigned int flags, int value);

/*
 * Rearrange the waiting queues so that threads waiting on a futex address
 * start waiting on a different address. Prior to requeueing, a thread may
 * be woken up if 'wake_one' is set. If FUTEX_BROADCAST is set, all threads
 * are moved instead of just one.
 */
int futex_requeue(void *src_addr, void *dst_addr,
                  unsigned int flags, bool wake_one);

#endif
