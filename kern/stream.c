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
 */

#include <kern/stream.h>
#include <kern/console.h>

struct console_stream
{
  struct stream base;
  unsigned long flags;
};

static struct console_stream console_stream_storage;

struct stream *console_stream;

static void
console_stream_write (struct stream *strm, const void *data, uint32_t bytes)
{
  (void)strm;
  console_puts_nolock (data, bytes);
}

static int32_t
console_stream_read (struct stream *strm, void *data, uint32_t bytes)
{
  (void)strm;
  return ((int32_t)console_gets_nolock ((char *)data, bytes));
}

static void
console_stream_lock (struct stream *strm)
{
  console_lock (&((struct console_stream *)strm)->flags);
}

static void
console_stream_unlock (struct stream *strm)
{
  console_unlock (((struct console_stream *)strm)->flags);
}

static const struct stream_ops console_stream_ops =
{
  .write = console_stream_write,
  .read = console_stream_read,
  .lock = console_stream_lock,
  .unlock = console_stream_unlock
};

static void
string_stream_write (struct stream *strm, const void *data, uint32_t bytes)
{
  _Auto ssp = (struct string_stream *) strm;
  if (ssp->cur >= ssp->size)
    return;

  size_t left = MIN (ssp->size - ssp->cur, bytes);
  memcpy (ssp->ptr + ssp->cur, data, left);
  ssp->cur += left;
}

static int32_t
string_stream_read (struct stream *strm, void *out, uint32_t bytes)
{
  _Auto ssp = (struct string_stream *) strm;
  if (ssp->cur >= ssp->size)
    return (0);

  size_t left = MIN (ssp->size - ssp->cur, bytes);
  memcpy (out, ssp->ptr + ssp->cur, left);
  ssp->cur += left;
  return ((int32_t)left);
}

static const struct stream_ops string_stream_ops =
{
  .write = string_stream_write,
  .read = string_stream_read,
};

int string_stream_init (struct string_stream *strm,
                        char *ptr, size_t size)
{
  if (!strm || !ptr)
    return (EFAULT);

  strm->ptr = ptr;
  strm->size = size;
  strm->cur = 0;
  strm->base.ops = &string_stream_ops;
  return (0);
}

static int __init
stream_setup (void)
{
  console_stream = &console_stream_storage.base;
  stream_init (console_stream, &console_stream_ops);
  return (0);
}

INIT_OP_DEFINE (stream_setup,
                INIT_OP_DEP (console_setup, true));
