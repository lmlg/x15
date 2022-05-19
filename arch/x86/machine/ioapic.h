/*
 * Copyright (c) 2017 Richard Braun.
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

#ifndef KERN_IOAPIC_H
#define KERN_IOAPIC_H

#include <stdbool.h>
#include <stdint.h>

// Initialize the ioapic module.
void ioapic_setup (void);

// Register an I/O APIC controller.
void ioapic_register (uint32_t apic_id, uintptr_t addr, uint32_t gsi_base);

// Report an interrupt source override.
void ioapic_override (uint8_t source, uint32_t gsi,
                      bool active_high, bool edge_triggered);

#endif
