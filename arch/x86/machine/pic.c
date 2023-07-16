/*
 * Copyright (c) 2012-2018 Richard Braun.
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

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>

#include <kern/error.h>
#include <kern/init.h>
#include <kern/intr.h>
#include <kern/panic.h>
#include <machine/cpu.h>
#include <machine/io.h>
#include <machine/lapic.h>
#include <machine/pic.h>

// I/O ports.
#define PIC_PRIMARY_CMD      0x20
#define PIC_PRIMARY_IMR      0x21
#define PIC_SECONDARY_CMD       0xa0
#define PIC_SECONDARY_IMR       0xa1

// Register bits.
#define PIC_ICW1_IC4        0x01
#define PIC_ICW1_INIT       0x10
#define PIC_ICW4_8086       0x01
#define PIC_OCW3_ISR        0x0b
#define PIC_EOI             0x20

// Special interrupts.
#define PIC_SECONDARY_INTR      2
#define PIC_SPURIOUS_INTR   7

static uint32_t pic_nr_secondary_intrs;

static uint8_t pic_primary_mask;
static uint8_t pic_secondary_mask;

static uint8_t pic_primary_spurious_intr;
static uint8_t pic_secondary_spurious_intr;

static bool
pic_is_secondary_intr (uint32_t intr)
{
  assert (intr <= PIC_MAX_INTR);
  return (intr >= PIC_NR_INTRS);
}

static void
pic_inc_secondary_intrs (void)
{
  if (! pic_nr_secondary_intrs)
    {
      pic_primary_mask |= 1 << PIC_SECONDARY_INTR;
      io_write_byte (PIC_PRIMARY_IMR, pic_primary_mask);
    }

  ++pic_nr_secondary_intrs;
  assert (pic_nr_secondary_intrs != 0);
}

static void
pic_dec_secondary_intrs (void)
{
  assert (pic_nr_secondary_intrs);

  if (--pic_nr_secondary_intrs == 0)
    {
      pic_primary_mask &= ~(1 << PIC_SECONDARY_INTR);
      io_write_byte (PIC_PRIMARY_IMR, pic_primary_mask);
    }
}

static void
pic_eoi (size_t intr)
{
  if (intr >= PIC_NR_INTRS)
    io_write_byte (PIC_SECONDARY_CMD, PIC_EOI);

  io_write_byte (PIC_PRIMARY_CMD, PIC_EOI);
}

static uint8_t
pic_read_isr (uint16_t port)
{
  io_write_byte (port, PIC_OCW3_ISR);
  return (io_read_byte (port));
}

static void
pic_ops_enable (void *priv __unused, uint32_t intr, uint32_t cpu __unused)
{
  if (pic_is_secondary_intr (intr))
    {
      pic_secondary_mask &= ~ (1 << (intr - PIC_NR_INTRS));
      io_write_byte (PIC_SECONDARY_IMR, pic_secondary_mask);
      pic_inc_secondary_intrs ();
    }
  else
    {
      pic_primary_mask &= ~(1 << intr);
      io_write_byte (PIC_PRIMARY_IMR, pic_primary_mask);
    }
}

static void
pic_ops_disable (void *priv __unused, uint32_t intr)
{
  if (pic_is_secondary_intr (intr))
    {
      pic_dec_secondary_intrs ();
      pic_secondary_mask |= 1 << (intr - PIC_NR_INTRS);
      io_write_byte (PIC_SECONDARY_IMR, pic_secondary_mask);
    }
  else
    {
      pic_primary_mask |= 1 << intr;
      io_write_byte (PIC_PRIMARY_IMR, pic_primary_mask);
    }
}

static void
pic_ops_eoi (void *priv __unused, uint32_t intr)
{
  pic_eoi (intr);
}

static const struct intr_ops pic_ops =
{
  .enable = pic_ops_enable,
  .disable = pic_ops_disable,
  .eoi = pic_ops_eoi,
};

static void
pic_intr (uint32_t vector)
{
  intr_handle (vector - CPU_EXC_INTR_FIRST);
}

static void __init
pic_register (void)
{
  intr_register_ctl (&pic_ops, NULL, 0, PIC_MAX_INTR);
  for (uint32_t intr = 0; intr <= PIC_MAX_INTR; intr++)
    cpu_register_intr (CPU_EXC_INTR_FIRST + intr, pic_intr);
}

static int
pic_spurious_intr (void *arg)
{
  uint8_t intr = *(const uint8_t *)arg;

  if (arg == &pic_primary_spurious_intr)
    {
      uint8_t isr = pic_read_isr (PIC_PRIMARY_CMD);
      if (isr & (1 << PIC_SPURIOUS_INTR))
        panic ("pic: real interrupt %hhu", intr);
    }
  else
    {
      uint8_t isr = pic_read_isr (PIC_SECONDARY_CMD);
      if (isr & (1 << PIC_SPURIOUS_INTR))
        panic ("pic: real interrupt %hhu", intr);

      pic_eoi (PIC_SECONDARY_INTR);
    }

  return (0);
}

static void __init
pic_setup_common (bool register_ctl)
{
  pic_nr_secondary_intrs = 0;
  pic_primary_mask = 0xff;
  pic_secondary_mask = 0xff;

  // ICW 1 - State that ICW 4 will be sent.
  io_write_byte (PIC_PRIMARY_CMD, PIC_ICW1_INIT | PIC_ICW1_IC4);
  io_write_byte (PIC_SECONDARY_CMD, PIC_ICW1_INIT | PIC_ICW1_IC4);

  // ICW 2.
  io_write_byte (PIC_PRIMARY_IMR, CPU_EXC_INTR_FIRST);
  io_write_byte (PIC_SECONDARY_IMR, CPU_EXC_INTR_FIRST + PIC_NR_INTRS);

  // ICW 3 - Set up cascading.
  io_write_byte (PIC_PRIMARY_IMR, 1 << PIC_SECONDARY_INTR);
  io_write_byte (PIC_SECONDARY_IMR, PIC_SECONDARY_INTR);

  // ICW 4 - Set 8086 mode.
  io_write_byte (PIC_PRIMARY_IMR, PIC_ICW4_8086);
  io_write_byte (PIC_SECONDARY_IMR, PIC_ICW4_8086);

  // OCW 1 - Mask all interrupts.
  io_write_byte (PIC_PRIMARY_IMR, pic_primary_mask);
  io_write_byte (PIC_SECONDARY_IMR, pic_secondary_mask);

  if (register_ctl)
    pic_register ();

  pic_primary_spurious_intr = PIC_SPURIOUS_INTR;
  int error = intr_register (pic_primary_spurious_intr, pic_spurious_intr,
                             &pic_primary_spurious_intr);
  error_check (error, __func__);

  pic_secondary_spurious_intr = PIC_NR_INTRS + PIC_SPURIOUS_INTR;
  error = intr_register (pic_secondary_spurious_intr, pic_spurious_intr,
                         &pic_secondary_spurious_intr);
  error_check (error, __func__);
}

void __init
pic_setup (void)
{
  pic_setup_common (true);
}

void __init
pic_setup_disabled (void)
{
  pic_setup_common (false);
}
