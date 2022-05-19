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
 *
 *
 * Machine-independent interrupt management.
 */

#ifndef KERN_INTR_H
#define KERN_INTR_H

#include <kern/init.h>

/*
 * Type for interrupt handler functions.
 *
 * Return codes :
 *  - 0             Interrupt successfully handled
 *  - EAGAIN        Spurious interrupt
 */
typedef int (*intr_handler_fn_t) (void *);

/*
 * Operations of an interrupt controller.
 *
 * Operations for interrupts targeting the same processor are serialized.
 */
struct intr_ops
{
  void (*enable) (void *priv, uint32_t, uint32_t);
  void (*disable) (void *priv, uint32_t);
  void (*eoi) (void *priv, uint32_t);
};

/*
 * Register an interrupt controller.
 *
 * This function isn't thread-safe and can only be called during system
 * initialization.
 */
void intr_register_ctl (const struct intr_ops *ops, void *priv,
                        uint32_t first_intr, uint32_t last_intr);

// Register/unregister an interrupt handler.
int intr_register (uint32_t intr, intr_handler_fn_t fn, void *arg);
void intr_unregister (uint32_t intr, intr_handler_fn_t fn);

// Handle an interrupt.
void intr_handle (uint32_t intr);

/*
 * This init operation provides :
 *  - registration of interrupt controllers and handlers
 */
INIT_OP_DECLARE (intr_bootstrap);

/*
 * This init operation provides :
 *  - all interrupt controllers have been registered
 *  - module fully initialized
 */
INIT_OP_DECLARE (intr_setup);

#endif
