/*
 * Copyright (c) 2023 Agustina Arzille.
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

#include <kern/fixup.h>
#include <kern/thread.h>

void
fixup_link (struct fixup *fx)
{
  struct thread *self = thread_self ();
  fx->prev = &self->fixup;
  fx->next = *fx->prev;
  self->fixup = fx;
  fx->value = 0;
}

void
fixup_restore (struct fixup *fx, int val)
{
  fx->value = val;
  __builtin_longjmp (fx->ctx, 1);
}
