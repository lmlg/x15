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
 */

#include <stdio.h>

#include <kern/symbol.h>
#include <kern/thread.h>
#include <kern/unwind.h>

#include <machine/cpu.h>
#include <machine/pmap.h>

// Miscelaneous constants used by the DWARF unwinder.
#define DW_EH_PE_absptr     0x00
#define DW_EH_PE_signed     0x09
#define DW_EH_PE_pcrel      0x10
#define DW_EH_PE_aligned    0x50
#define DW_EH_PE_indirect   0x80
#define DW_EH_PE_omit       0xff

// Encoding types for DWARF.
enum
{
  DW_EH_PE_uleb128 = 0x01,
  DW_EH_PE_udata2,
  DW_EH_PE_udata4,
  DW_EH_PE_udata8,
  DW_EH_PE_sleb128 = DW_EH_PE_uleb128 | DW_EH_PE_signed,
  DW_EH_PE_sdata2,
  DW_EH_PE_sdata4,
  DW_EH_PE_sdata8
};

// Register save states.
enum
{
  DW_RULE_SAME,
  DW_RULE_UNDEF,
  DW_RULE_OFFSET,
  DW_RULE_REG,
};

// DWARF opcodes.
#define DW_CFA_nop                  0x00
#define DW_CFA_set_loc              0x01
#define DW_CFA_advance_loc1         0x02
#define DW_CFA_advance_loc2         0x03
#define DW_CFA_advance_loc4         0x04
#define DW_CFA_offset_extended      0x05
#define DW_CFA_undefined            0x07
#define DW_CFA_same_value           0x08
#define DW_CFA_register             0x09
#define DW_CFA_remember_state       0x0a
#define DW_CFA_restore_state        0x0b
#define DW_CFA_def_cfa              0x0c
#define DW_CFA_def_cfa_register     0x0d
#define DW_CFA_def_cfa_offset       0x0e
#define DW_CFA_offset_extended_sf   0x11
#define DW_CFA_def_cfa_sf           0x12
#define DW_CFA_def_cfa_offset_sf    0x13
#define DW_CFA_val_offset           0x14
#define DW_CFA_val_offset_sf        0x15
#define DW_CFA_GNU_args_size        0x2e
#define DW_CFA_advance_loc          0x40
#define DW_CFA_offset               0x80
#define DW_CFA_restore              0xc0

#define UNW_SP_REGISTER   __builtin_dwarf_sp_column ()
#define UNW_RA(x)   __builtin_extract_return_addr ((void *)(x))

const struct unw_globals *volatile unw_globals_ptr __weak;

/*
 * A register save state can be defined in terms of:
 * - Another register.
 * - An offset within the CFA.
 * - An arbitrary expression (Not yet supported).
 */

struct unw_frame_regs
{
  uint8_t rules[CPU_UNWIND_REGISTERS];
  union
    {
      uint16_t reg;
      int16_t off;
    } values[CPU_UNWIND_REGISTERS];
  struct
    {
      int rule;
      uint16_t reg;
      int16_t off;
    } cfa;
};

struct unw_cursor
{
  struct unw_mcontext *mctx;
  struct unw_frame_regs cols;
};

static void
unw_cursor_clear (struct unw_cursor *cursor)
{
  memset (&cursor->cols, 0, sizeof (cursor->cols));
}

static void
unw_cursor_init_mctx (struct unw_cursor *cursor, struct unw_mcontext *mctx)
{
  unw_cursor_clear (cursor);
  cursor->mctx = mctx;
}

static const struct unw_fde*
unw_fde_lookup (uintptr_t pc, const struct unw_globals *globals)
{
  if (pc < globals->base_addr)
    return (NULL);

  uint32_t base = (uint32_t)(pc - globals->base_addr);
  const struct unw_fde *fdes = globals->fdes;

  // Binary search over the FDE's.
  for (uint32_t n = globals->nr_fdes; n > 0; )
    {
      _Auto fde = &fdes[n / 2];
      if (base < fde->base_off)
        n /= 2;
      else if (base > fde->base_off + fde->addr_range)
        {
          fdes = fde + 1;
          n -= n / 2 + 1;
        }
      else
        return (fde);
    }

  return (NULL);
}

static uintptr_t
unw_read_uleb (const unsigned char **ptr)
{
  // Read an unsigned LEB-128 value and update the source pointer.
  const unsigned char *p = *ptr;
  for (uintptr_t ret = 0, shift = 0 ; ; shift += 7)
    {
      uintptr_t byte = *p++;
      ret |= (byte & 0x7f) << shift;
      if (!(byte & 0x80))
        {
          *ptr = p;
          return (ret);
        }
    }
}

static intptr_t
unw_read_sleb (const unsigned char **ptr)
{
  // Read a signed LEB-128 value and update the source pointer.
  intptr_t ret = 0;
  uint32_t shift = 0, byte;
  const unsigned char *p = *ptr;

  do
    {
      byte = *p++;
      ret |= ((uintptr_t)byte & 0x7f) << shift;
      shift += 7;
    }
  while (byte & 0x80);

  if (shift < 8 * sizeof (ret) && (byte & 0x40))
    ret |= -(((uintptr_t)1) << shift);

  *ptr = p;
  return (ret);
}

static int
unw_read_safe (uintptr_t addr, uintptr_t *out)
{
  if (addr < PMAP_START_KERNEL_ADDRESS ||
      addr > PMAP_END_KERNEL_ADDRESS)
    return (-EFAULT);

  *out = *(uintptr_t *)addr;
  return (0);
}

static int
unw_read_encptr (uint8_t enc, const unsigned char **ptr,
                 uintptr_t pc, uintptr_t *out)
{
  const unsigned char *p = *ptr;
  if (enc == DW_EH_PE_omit)
    {
      *out = 0;
      return (0);
    }
  else if (enc == DW_EH_PE_aligned)
    {
      size_t size = sizeof (uintptr_t) - 1;
      p = (const unsigned char *)(((uintptr_t)p + size) & ~size);
      if (unw_read_safe ((uintptr_t)p, out) != 0)
        return (-EFAULT);

      *ptr = p + sizeof (uintptr_t);
      return (0);
    }

  uintptr_t base;
  switch (enc & 0x70)
    {
      case DW_EH_PE_absptr:
        base = 0;
        break;
      case DW_EH_PE_pcrel:
        base = pc;
        break;
      default:
        return (-EINVAL);
    }

  if ((enc & 0x7) == 0)
#ifdef __LP64__
    enc |= DW_EH_PE_udata8;
#else
    enc |= DW_EH_PE_udata4;
#endif

  uintptr_t ret;
  switch (enc & 0xf)
    {
      case DW_EH_PE_uleb128:
        ret = base + unw_read_uleb (&p);
        break;

      case DW_EH_PE_sleb128:
        ret = base + unw_read_sleb (&p);
        break;

#define UNW_UDATA(type, enc_val)   \
  case DW_EH_PE_##enc_val:   \
    {   \
      type tmp;   \
      memcpy (&tmp, p, sizeof (tmp));   \
      p += sizeof (tmp);   \
      ret = base + tmp;   \
    }   \
    break

      UNW_UDATA (uint16_t, udata2);
      UNW_UDATA (int16_t,  sdata2);
      UNW_UDATA (uint32_t, udata4);
      UNW_UDATA (int32_t,  sdata4);
      UNW_UDATA (uint64_t, udata8);
      UNW_UDATA (int64_t,  sdata8);

#undef UNW_UDATA

      default:
        return (-EINVAL);
    }

  if (enc & DW_EH_PE_indirect)
    {
      p = (const unsigned char *)(uintptr_t)ret;
      if (unw_read_safe ((uintptr_t)p, &ret) != 0)
        return (-EFAULT);
    }

  *ptr = p;
  *out = ret;
  return (0);
}

static int
unw_cursor_set_column (struct unw_cursor *cursor, size_t column,
                       int rule, uintptr_t val)
{
  if (column >= ARRAY_SIZE (cursor->cols.rules))
    return (-EFAULT);

  cursor->cols.rules[column] = rule;
  cursor->cols.values[column].reg = val;
  return (0);
}

static uintptr_t
unw_cursor_pc (const struct unw_cursor *cursor)
{
  return (cursor->mctx->regs[CPU_UNWIND_PC_REG]);
}

static void
unw_cursor_set_pc (struct unw_cursor *cursor, uintptr_t pc)
{
  cursor->mctx->regs[CPU_UNWIND_PC_REG] = pc;
}

static uintptr_t
unw_cursor_sp (const struct unw_cursor *cursor)
{
  return (cursor->mctx->regs[UNW_SP_REGISTER]);
}

static void
unw_cursor_set_sp (struct unw_cursor *cursor, uintptr_t sp)
{
  cursor->mctx->regs[UNW_SP_REGISTER] = sp;
}

#define UNW_CURSOR_SET_COLUMN(cursor, column, rule, val)   \
  do   \
    {   \
      int error_ = unw_cursor_set_column (cursor, column, rule,   \
                                          (uintptr_t)(val));   \
      if (error_)   \
        return (error_);   \
    }   \
  while (0)

static int
unw_run_dw (struct unw_cursor *cursor, const struct unw_cie *cie,
            const unsigned char *ops, uintptr_t pc)
{
  struct unw_frame_regs free_regs[4];
  uint32_t free_idx = 0;
  intptr_t sarg;
  uintptr_t regno, arg = unw_read_uleb (&ops);
  _Auto ops_end = ops + arg;

  while (pc < unw_cursor_pc (cursor) && ops < ops_end)
    {
      uint8_t operand = 0, op = *ops++;
      if (op & 0xc0)
        {
          operand = op & 0x3f;
          op &= ~0x3f;
        }

      switch (op)
        {
          case DW_CFA_set_loc:
            if (unw_read_encptr (cie->code_enc, &ops, pc, &pc) < 0)
              return (-1);
            break;

          case DW_CFA_advance_loc:
            pc += operand * cie->code_align;
            break;

          case DW_CFA_advance_loc1:
            pc += (*ops++) * cie->code_align;
            break;

          case DW_CFA_advance_loc2:
            {
              uint16_t off;
              memcpy (&off, ops, sizeof (off));
              ops += sizeof (off);
              pc += off * cie->code_align;
              break;
            }

          case DW_CFA_advance_loc4:
            {
              uint32_t off;
              memcpy (&off, ops, sizeof (off));
              ops += sizeof (off);
              pc += off * cie->code_align;
              break;
            }

          case DW_CFA_def_cfa:
            cursor->cols.cfa.reg = unw_read_uleb (&ops);
            cursor->cols.cfa.off = unw_read_uleb (&ops);
            cursor->cols.cfa.rule = DW_RULE_REG;
            break;

          case DW_CFA_def_cfa_sf:
            cursor->cols.cfa.reg = unw_read_uleb (&ops);
            cursor->cols.cfa.off = unw_read_sleb (&ops) * cie->data_align;
            cursor->cols.cfa.rule = DW_RULE_REG;
            break;

          case DW_CFA_def_cfa_offset:
            cursor->cols.cfa.off = unw_read_uleb (&ops);
            break;

          case DW_CFA_def_cfa_register:
            cursor->cols.cfa.reg = unw_read_uleb (&ops);
            cursor->cols.cfa.rule = DW_RULE_REG;
            break;

          case DW_CFA_offset:
            arg = unw_read_uleb (&ops);
            unw_cursor_set_column (cursor, operand, DW_RULE_OFFSET,
                                   arg * cie->data_align);
            break;

          case DW_CFA_offset_extended:
            regno = unw_read_uleb (&ops);
            arg = unw_read_uleb (&ops);
            unw_cursor_set_column (cursor, regno, DW_RULE_OFFSET,
                                   arg * cie->data_align);
            break;

          case DW_CFA_offset_extended_sf:
            regno = unw_read_uleb (&ops);
            sarg = unw_read_sleb (&ops);
            unw_cursor_set_column (cursor, regno, DW_RULE_OFFSET,
                                   sarg * cie->data_align);
            break;

          case DW_CFA_undefined:
          case DW_CFA_same_value:
            regno = unw_read_uleb (&ops);
            unw_cursor_set_column (cursor, regno, op == DW_CFA_undefined ?
                                   DW_RULE_UNDEF : DW_RULE_SAME, 0);
            break;

          case DW_CFA_register:
            regno = unw_read_uleb (&ops);
            arg = unw_read_uleb (&ops);
            unw_cursor_set_column (cursor, regno, DW_RULE_REG, arg);
            break;

          case DW_CFA_nop:
            break;

          case DW_CFA_GNU_args_size:
            (void)unw_read_uleb (&ops);
            break;

          case DW_CFA_remember_state:
            if (free_idx >= ARRAY_SIZE (free_regs))
              return (-ENOMEM);

            free_regs[free_idx++] = cursor->cols;
            break;

          case DW_CFA_restore_state:
            if (! free_idx)
              return (-EINVAL);

            cursor->cols = free_regs[--free_idx];
            break;

          case DW_CFA_restore:
            if (operand >= ARRAY_SIZE (cursor->cols.rules))
              return (-EFAULT);
            cursor->cols.rules[operand] = DW_RULE_SAME;
            break;

          default:
            return (-EINVAL);
        }
    }

  return (0);
}

static int
unw_apply_regs (struct unw_cursor *cursor, const struct unw_cie *cie)
{
  _Auto cols = &cursor->cols;

  // Compute the CFA first, as further expressions may depend on it.
  if (cols->cfa.reg >= ARRAY_SIZE (cursor->mctx->regs))
    return (-EFAULT);
  else if (cols->cfa.rule != DW_RULE_REG)
    return (-EINVAL);

  uintptr_t *regs = cursor->mctx->regs,
            cfa = regs[cols->cfa.reg] + cols->cfa.off;

  for (size_t i = 0; i < ARRAY_SIZE (cols->rules); ++i)
    switch (cols->rules[i])
      {
        case DW_RULE_UNDEF:
        case DW_RULE_SAME:
          break;
        case DW_RULE_OFFSET:
          if (unw_read_safe (cfa + cols->values[i].off, &regs[i]) != 0)
            return (-EFAULT);
          break;
        case DW_RULE_REG:
          {
            _Auto rx = cols->values[i].reg;
            if (unlikely (rx >= ARRAY_SIZE (cursor->mctx->regs)) ||
                unw_read_safe (regs[rx], &regs[i]) != 0)
              return (-EFAULT);

            break;
          }

        default:
          return (-EINVAL);
      }

  if (cie->ret_addr >= ARRAY_SIZE (cols->rules))
    return (-EINVAL);
  else if (cols->rules[cie->ret_addr] == DW_RULE_UNDEF)
    {
      unw_cursor_set_pc (cursor, 0);
      return (0);
    }

  void *pc = UNW_RA (regs[cie->ret_addr]);
  unw_cursor_set_pc (cursor, (uintptr_t)pc);
  unw_cursor_set_sp (cursor, cfa);
  return (pc != 0);
}

static int
unw_cursor_step (struct unw_cursor *cursor)
{
  _Auto gd = unw_globals_ptr;
  _Auto fde = unw_fde_lookup (unw_cursor_pc (cursor) - 1, gd);
  if (! fde)
    return (-1);

  uintptr_t initial_loc = fde->base_off + gd->base_addr;
  _Auto cie = &gd->cies[fde->idxs & 0xff];

  // Run the CIE initialization ops.
  int rv = unw_run_dw (cursor, cie, gd->ops + cie->ops_idx, initial_loc);
  if (rv < 0)
    return (rv);

  // Run the FDE ops to unwind the stack.
  rv = unw_run_dw (cursor, cie, gd->ops + (fde->idxs >> 8), initial_loc);
  if (rv == 0)
    // If successful, set the registers to their new values.
    rv = unw_apply_regs (cursor, cie);

  // Clear the cursor for the next run.
  unw_cursor_clear (cursor);
  return (rv);
}

int
unw_backtrace (struct unw_mcontext *mctx,
               int (*fn) (struct unw_mcontext *, void *), void *arg)
{
  struct unw_cursor cursor;

  if (! mctx)
    {
      mctx = alloca (sizeof (*mctx));
      cpu_unw_mctx_save (mctx->regs);
    }

  unw_cursor_init_mctx (&cursor, mctx);
  while (1)
    {
      int error = fn (cursor.mctx, arg);
      if (error)
        return (error);
      else if (unw_cursor_step (&cursor) <= 0)
        return (0);
    }
}

static int
unw_show_stacktrace (struct unw_mcontext *mctx, void *arg)
{
  uintptr_t pc = mctx->regs[CPU_UNWIND_PC_REG];
  const struct symbol *sym = symbol_lookup (pc);
  uint32_t index = (*(uint32_t *)arg)++;

  if (! sym)
    printf ("#%02u [%#010lx]\n", index, pc);
  else
    printf ("#%02u [%#010lx] %s+%#lx/%#lx\n", index, pc,
            sym->name, pc - sym->addr, sym->size);

  return (0);
}

void
unw_stacktrace (struct unw_mcontext *mctx)
{
  uint32_t index = 0;
  unw_backtrace (mctx, unw_show_stacktrace, &index);
}

int
unw_fixup_save (struct unw_fixup_t *fx)
{
  __builtin_unwind_init ();
  fx->sp = (uintptr_t)__builtin_dwarf_cfa ();
  fx->pc = (uintptr_t)UNW_RA (__builtin_return_address (0));

  struct thread *self = thread_self ();
  fx->prev = &self->fixup;
  fx->next = *fx->prev;

  self->fixup = fx;
  return (0);
}

static int
unw_fixup_step_until (struct unw_fixup_t *fixup, struct unw_cursor *cursor)
{
  int rv = 1;
  while (unw_cursor_sp (cursor) < fixup->sp)
    {
      rv = unw_cursor_step (cursor);
      if (rv <= 0)
        break;
    }

  return (rv);
}

void
unw_fixup_restore (struct unw_fixup_t *fixup,
                   struct unw_mcontext *mctx, int retval)
{
  struct unw_cursor cursor;
  unw_cursor_init_mctx (&cursor, mctx);

  if (unw_fixup_step_until (fixup, &cursor) <= 0)
    return;

  unw_cursor_set_pc (&cursor, fixup->pc);
  unw_cursor_set_sp (&cursor, fixup->sp);
  cpu_unw_mctx_set_frame (cursor.mctx->regs, retval);
  __builtin_unreachable ();
}

void
unw_fixup_jmp (struct unw_fixup_t *fixup, int retval)
{
  struct unw_cursor cursor;
  struct unw_mcontext mctx;

  cpu_unw_mctx_save (mctx.regs);
  unw_cursor_init_mctx (&cursor, &mctx);

  if (unw_fixup_step_until (fixup, &cursor) > 0)
    {
      unw_cursor_set_sp (&cursor, fixup->sp);
      unw_cursor_set_pc (&cursor, fixup->pc);
      cpu_unw_mctx_jmp (cursor.mctx->regs, retval);
    }

  __builtin_unreachable ();
}
