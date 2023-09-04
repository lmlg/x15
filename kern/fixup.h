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
 * Fixups for faults.
 */

#ifndef KERN_FIXUP_H
#define KERN_FIXUP_H

#include <stdint.h>
#include <stdnoreturn.h>

struct fixup
{
  void *ctx[5];
  struct fixup *next;
  struct fixup **prev;
  int value;
};

// Chain the fixup to the current thread's list of fixups.
void fixup_link (struct fixup *fx);

// Save the calling environment in FXP. Always returns 0.
#define fixup_save(fxp)   \
  ({   \
     struct fixup *fx_ = (fxp);   \
     fixup_link (fx_);   \
     __builtin_setjmp (fx_->ctx);   \
     fx_->value;   \
   })

#define fixup_save2(fxp)   \
  ({   \
     struct fixup *fx_ = (fxp);   \
     struct thread *self_ = thread_self ();   \
     fx_->prev = &self_->fixup;   \
     fx_->next = *fx_->prev;   \
     self_->fixup = fx_;   \
     fx_->value = 0;   \
     __builtin_setjmp (fx_->ctx);   \
     fx_->value;   \
   })

/*
 * Restore the environment saved in FX, making the 'fixup_save'
 * call return VAL, which must be nonzero.
 */
noreturn void fixup_restore (struct fixup *fx, int val);

// Fixup guards.

static inline void
fixup_fini (void *p)
{
  struct fixup *fx = p;
  *fx->prev = fx->next;
}

#define FIXUP(name)   CLEANUP (fixup_fini) struct fixup name

#endif
