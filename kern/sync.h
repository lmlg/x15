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
 * Common definitions for synchronization utilities.
 */

#ifndef KERN_SYNC_H
#define KERN_SYNC_H

#include <stdint.h>

/*
 * Synchronization key used to identify wait queues.
 */
struct sync_key {
    uintptr_t u;
    uintptr_t v;
};

/*
 * Initialize a sync key.
 */
static inline void
sync_key_init(struct sync_key *key)
{
    key->u = key->v = 0;
}

/*
 * Test that a key is empty initialized.
 */
static inline bool
sync_key_empty(const struct sync_key *key)
{
    return key->u == 0 && key->v == 0;
}

/*
 * Set a sync key to a generic pointer.
 */
static inline void
sync_key_setptr(struct sync_key *key, const void *ptr)
{
    key->u = (uintptr_t)ptr;
    key->v = 0;
}

/*
 * Test for sync keys equality.
 */
static inline bool
sync_key_eq(const struct sync_key *a, const struct sync_key *b)
{
    return a->u == b->u && a->v == b->v;
}

/*
 * Compute the hash code for a key.
 */
static inline uintptr_t
sync_key_hash(const struct sync_key *key)
{
    return ((key->u << 5) | (key->u >> (sizeof(uintptr_t) * 8 - 5))) ^ key->v;
}

#endif
