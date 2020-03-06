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

int futex_wait(int *addr, int value, unsigned int flags, uint64_t ticks);

int futex_wake(int *addr, unsigned int flags, int value);

int futex_requeue(int *src_addr, int *dst_addr,
                  unsigned int flags, bool wake_one);

#endif
