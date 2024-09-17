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
 * Generic runtime stack unwinding.
 */

#ifndef KERN_UNWIND_H
#define KERN_UNWIND_H

#include <stdint.h>
#include <stdnoreturn.h>

#include <kern/macros.h>

#include <machine/cpu.h>

#define __unwind   __section (".unwind")

// Common information element.
struct unw_cie
{
  uintptr_t code_align;
  uintptr_t ret_addr;
  intptr_t data_align;
  uint8_t code_enc;
  uint16_t ops_idx;
};

// Frame descriptor element.
struct unw_fde
{
  uint32_t base_off;   // Difference relative to the base address.
  uint32_t addr_range;   // Range in bytes for this FDE.
  uint32_t idxs;   // CIE index (low 8 bits) and opcode index (high 24 bits).
};

// DWARF global data - Exported by the unwind table generator.
struct unw_globals
{
  uint32_t nr_fdes;
  const struct unw_fde *fdes;
  const struct unw_cie *cies;
  const unsigned char *ops;
  uintptr_t base_addr;
};

// Machine context used for unwinding and stack tracing.
struct unw_mcontext
{
  uintptr_t regs[CPU_UNWIND_REGISTERS];
};

// Saved information needed for fixups.
struct unw_fixup_t
{
  uintptr_t sp;
  uintptr_t bp;
  uintptr_t pc;
  struct unw_fixup_t *next;
  struct unw_fixup_t **prev;
};

int unw_fixup_save (struct unw_fixup_t *fixup, void *frame)
  __attribute__ ((returns_twice));

// Save the calling environemt in FIXUP. Always returns zero.
#define unw_fixup_save(fx)   \
  (unw_fixup_save) ((fx), __builtin_frame_address (0))

/*
 * Restore the environment saved in FIXUP, starting the unwind process
 * from CTX. Makes the 'unw_fixup_save' return RETVAL.
 */
void unw_fixup_restore (struct unw_fixup_t *fixup,
                        struct unw_mcontext *ctx, int retval);

/*
 * Same as above, only this function uses the current machine context
 * instead of a user-provided one, and doesn't handle failures in
 * the unwind process.
 */
noreturn void unw_fixup_jmp (struct unw_fixup_t *fixup, int retval);

/*
 * Perform a traceback, starting from the passed machine context (or the
 * current one, if null), applying the function with the registers and
 * argument. If a non-zero value is returned, the traceback stops immediately.
 */
int unw_backtrace (struct unw_mcontext *initial,
                   int (*fn) (struct unw_mcontext *, void *), void *arg);

/*
 * Print the stack trace originating in the provided context, if provided,
 * otherwise, use the current one.
 */
void unw_stacktrace (struct unw_mcontext *initial);

// Fixup guard.

static inline void
unw_fixup_fini (void *p)
{
  struct unw_fixup_t *fx = p;
  *fx->prev = fx->next;
}

#define unw_fixup   unw_fixup_t CLEANUP (unw_fixup_fini)

#endif
