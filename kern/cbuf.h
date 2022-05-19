/*
 * Copyright (c) 2015-2018 Richard Braun.
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
 * Upstream site with license notes :
 * http://git.sceen.net/rbraun/librbraun.git/
 *
 *
 * FIFO circular byte buffer.
 */

#ifndef KERN_CBUF_H
#define KERN_CBUF_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Circular buffer descriptor.
 *
 * The buffer capacity must be a power-of-two. Indexes are absolute values
 * which can overflow. Their difference cannot exceed the capacity.
 */
struct cbuf
{
  uint8_t *buf;
  size_t capacity;
  size_t start;
  size_t end;
};

static inline size_t
cbuf_capacity (const struct cbuf *cbuf)
{
  return (cbuf->capacity);
}

static inline size_t
cbuf_start (const struct cbuf *cbuf)
{
  return (cbuf->start);
}

static inline size_t
cbuf_end (const struct cbuf *cbuf)
{
  return (cbuf->end);
}

static inline size_t
cbuf_size (const struct cbuf *cbuf)
{
  return (cbuf->end - cbuf->start);
}

static inline size_t
cbuf_avail_size (const struct cbuf *cbuf)
{
  return (cbuf_capacity (cbuf) - cbuf_size (cbuf));
}

static inline void
cbuf_clear (struct cbuf *cbuf)
{
  cbuf->start = cbuf->end;
}

static inline bool
cbuf_range_valid (const struct cbuf *cbuf, size_t start, size_t end)
{
  return (end - start <= cbuf_size (cbuf) &&
          start - cbuf->start <= cbuf_size (cbuf) &&
          cbuf->end - end <= cbuf_size (cbuf));;
}

static inline bool
cbuf_index_valid (const struct cbuf *cbuf, size_t index)
{
  return (index - cbuf->start <= cbuf_size (cbuf) &&
          cbuf->end - index <= cbuf_size (cbuf));
}

/*
 * Initialize a circular buffer.
 *
 * The descriptor is set to use the given buffer for storage. Capacity
 * must be a power-of-two.
 */
void cbuf_init (struct cbuf *cbuf, void *buf, size_t capacity);

/*
 * Push data to a circular buffer.
 *
 * If the function isn't allowed to erase old data and the circular buffer
 * doesn't have enough unused bytes for the new data, EAGAIN is returned.
 */
int cbuf_push (struct cbuf *cbuf, const void *buf, size_t size, bool erase);

/*
 * Pop data from a circular buffer.
 *
 * On entry, the sizep argument points to the size of the output buffer.
 * On return, it is updated to the number of bytes actually transferred.
 *
 * If the buffer is empty, EAGAIN is returned, and the size of the output
 * buffer is unmodified.
 *
 * The output buffer may be NULL, in which case this function acts as if
 * it wasn't, but without writing output data.
 */
int cbuf_pop (struct cbuf *cbuf, void *buf, size_t *sizep);

/*
 * Push a byte to a circular buffer.
 *
 * If the function isn't allowed to erase old data and the circular buffer
 * is full, EAGAIN is returned.
 */
int cbuf_pushb (struct cbuf *cbuf, uint8_t byte, bool erase);

/*
 * Pop a byte from a circular buffer.
 *
 * If the buffer is empty, EAGAIN is returned.
 *
 * The output byte pointer may be NULL, in which case this function acts
 * as if it wasn't, but without writing output data.
 */
int cbuf_popb (struct cbuf *cbuf, void *bytep);

/*
 * Write into a circular buffer at a specific location.
 *
 * If the given index is outside buffer boundaries, EINVAL is returned.
 * The given [index, size) range may extend beyond the end of the circular
 * buffer.
 */
int cbuf_write (struct cbuf *cbuf, size_t index, const void *buf, size_t size);

/*
 * Read from a circular buffer at a specific location.
 *
 * On entry, the sizep argument points to the size of the output buffer.
 * On return, it is updated to the number of bytes actually transferred.
 *
 * If the given index is outside buffer boundaries, EINVAL is returned.
 *
 * The circular buffer isn't changed by this operation.
 *
 * The output buffer may be NULL, in which case this function acts as if
 * it wasn't, but without writing output data.
 */
int cbuf_read (const struct cbuf *cbuf, size_t index, void *buf, size_t *sizep);

/*
 * Set the value of the start/end index.
 *
 * These functions provide low level access to the circular buffer boundaries
 * while making sure its size doesn't exceed its capacity.
 *
 * Users should try and find a higher level way to manipulate the circular
 * buffer, and only resort to using these functions if there's no other choice.
 */
void cbuf_set_start (struct cbuf *cbuf, size_t start);
void cbuf_set_end (struct cbuf *cbuf, size_t end);

#endif
