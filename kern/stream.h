/*
 * Copyright (c) 2022 Agustina Arzille.
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
 * Generic streams.
 */

#ifndef KERN_STREAM_H
#define KERN_STREAM_H   1

#include <stdint.h>
#include <string.h>

#include <kern/init.h>
#include <kern/macros.h>

struct stream;

struct stream_ops
{
  void (*write) (struct stream *, const void *, uint32_t);
  int32_t (*read) (struct stream *, void *, uint32_t);
  void (*lock) (struct stream *);
  void (*unlock) (struct stream *);
};

struct stream
{
  const struct stream_ops *ops;
};

struct string_stream
{
  struct stream base;
  char *ptr;
  size_t size;
  size_t cur;
};

static inline void
stream_init (struct stream *strm, const struct stream_ops *ops)
{
  strm->ops = ops;
}

// Lock/unlock a stream.

static inline void
stream_lock (struct stream *strm)
{
  if (strm->ops->lock)
    strm->ops->lock (strm);
}

static inline void
stream_unlock (struct stream *strm)
{
  if (strm->ops->unlock)
    strm->ops->unlock (strm);
}

// Read/Write to a stream.

static inline void
stream_write_unlocked (struct stream *strm, const void *data, uint32_t bytes)
{
  _Auto write_fn = strm->ops->write;
  if (write_fn)
    write_fn (strm, data, bytes);
}

static inline int32_t
stream_read_unlocked (struct stream *strm, void *out, uint32_t bytes)
{
  _Auto read_fn = strm->ops->read;
  return (read_fn ? read_fn (strm, out, bytes) : -1);
}

static inline void
stream_write (struct stream *strm, const void *data, uint32_t bytes)
{
  stream_lock (strm);
  stream_write_unlocked (strm, data, bytes);
  stream_unlock (strm);
}

static inline int32_t
stream_read (struct stream *strm, void *out, uint32_t bytes)
{
  stream_lock (strm);
  int32_t ret = stream_read_unlocked (strm, out, bytes);
  stream_unlock (strm);
  return (ret);
}

static inline void
stream_putc (struct stream *strm, int ch)
{
  char c = (char) ch;
  stream_write (strm, &c, 1);
}

static inline int
stream_getc (struct stream *strm)
{
  char c;
  return (stream_read (strm, &c, 1) == 1 ? (int)c : -1);
}

static inline void
stream_puts (struct stream *strm, const char *s)
{
  return (stream_write (strm, s, strlen (s)));
}

// String streams.
int string_stream_init (struct string_stream *strm, char *ptr, size_t size);

#define string_stream_create(ptr, size)   \
  ({   \
    struct string_stream *s_ = __builtin_alloca (sizeof (*s_));   \
    string_stream_init (s_, (ptr), (size)) == 0 ?   \
    (struct stream *)s_ : (struct stream *)NULL;   \
  })

// Standard console stream.

extern struct stream* console_stream;

// Init operation for streams. Sets up the standard streams.
INIT_OP_DECLARE (stream_setup);

#endif
