/*
 * Copyright (c) 2014-2017 Richard Braun.
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
 * Per-CPU variables.
 *
 * This module supports statically allocated per-CPU variables only. Each
 * active processor gets its own block of pages, called percpu area, where
 * percpu variables are stored. The offset of a percpu variable is fixed
 * and added to the base of the percpu area to obtain the real address of
 * the variable.
 *
 * A statically allocated percpu variable should be defined with the
 * __percpu macro, e.g. :
 *
 * struct s var __percpu;
 *
 * Obviously, the variable cannot be directly accessed. Instead, percpu
 * variables can be accessed with the following accessors :
 *  - percpu_ptr()
 *  - percpu_var()
 *
 * The cpu module is expected to provide the following accessors to access
 * percpu variables from the local processor :
 *  - cpu_local_ptr()
 *  - cpu_local_var()
 *
 * These accessors may generate optimized code.
 *
 * Architecture-specific code must enforce that the percpu section starts
 * at 0, thereby making the addresses of percpu variables offsets into the
 * percpu area. It must also make sure the _percpu and _percpu_end symbols
 * have valid virtual addresses, included between _init (but not part of
 * the init section) and _end.
 *
 * Unless otherwise specified, accessing a percpu variable is not
 * interrupt-safe.
 */

#ifndef KERN_PERCPU_H
#define KERN_PERCPU_H

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include <kern/init.h>
#include <kern/macros.h>
#include <kern/slist_types.h>

#define PERCPU_SECTION   .percpu
#define __percpu   __section(QUOTE(PERCPU_SECTION))

typedef void (*percpu_op_fn_t) (void);

/*
 * Per-CPU operation.
 *
 * These operations allow initialization code to register functions to be run
 * on APs when they're started.
 */
struct percpu_op
{
  struct slist_node node;
  percpu_op_fn_t fn;
};

#define PERCPU_OP_INITIALIZER(op_fn)   { .fn = op_fn }

/*
 * Boundaries of the percpu section.
 *
 * The addresses of these symbols must be valid, even if the percpu section
 * itself has different addresses.
 */
extern char _percpu;
extern char _percpu_end;

// Expands to the address of a percpu variable.
#define percpu_ptr(var, cpu)   \
  ((typeof (var) *)(percpu_area (cpu) + ((uintptr_t)(&(var)))))

// Expands to the lvalue of a percpu variable.
#define percpu_var(var, cpu)   (*percpu_ptr(var, cpu))

static inline void*
percpu_area (uint32_t cpu)
{
  extern void *percpu_areas[CONFIG_MAX_CPUS];

  assert (cpu < ARRAY_SIZE (percpu_areas));
  void *area = percpu_areas[cpu];
  assert (area);
  return (area);
}

/*
 * Register a percpu operation to be run on all processors when
 * they're started.
 *
 * The operation is run on the BSP when it's registered. It's run as late as
 * possible on APs, normally right before scheduling is enabled.
 */
void percpu_register_op (struct percpu_op *op);

/*
 * Register a processor.
 *
 * This function creates a percpu area from kernel virtual memory for the
 * given processor. The created area is filled from the content of the
 * percpu section.
 */
int percpu_add (uint32_t cpu);

/*
 * Run registered percpu operations on an AP.
 */
void percpu_ap_setup (void);

/*
 * This init operation provides :
 *  - access to percpu variables on processor 0
 */
INIT_OP_DECLARE (percpu_bootstrap);

/*
 * This init operation provides :
 *  - percpu operations can be registered
 *  - new percpu areas can be created
 *
 * The dependency that provides access to percpu variables on all processors
 * is cpu_mp_probe.
 *
 * TODO Add percpu alias to cpu_mp_probe.
 */
INIT_OP_DECLARE (percpu_setup);

#endif
