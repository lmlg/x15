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

// The saved context to which we may end up jumping.
struct unw_fixup_t
{
  uintptr_t sp;
  uintptr_t pc;
  struct unw_fixup_t *next;
  struct unw_fixup_t **prev;
};

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
  uint32_t idxs;   // CIE index (low 16 bits) and opcode index (high 16 bits).
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

// Save the information needed to perform stack unwinding up to that point.
int unw_fixup_save (struct unw_fixup_t *fixup);

// Restore the program state, saving it to a CPU frame.
int unw_fixup_restore (struct unw_fixup_t *fixup, void *area, int retval);

// Restore the saved program state and jump to it.
noreturn void unw_fixup_jmp (struct unw_fixup_t *fixup, int retval);

/* Print the stack trace originating in the provided context, if provided,
 * otherwise, use the current one. */
void unw_backtrace (struct unw_mcontext *initial);

// Unwind fixup guards.
static inline void
unw_fixup_fini (void *p)
{
  struct unw_fixup_t *fx = p;
  *fx->prev = fx->next;
}

#define unw_fixup   unw_fixup_t CLEANUP (unw_fixup_fini)

#endif
