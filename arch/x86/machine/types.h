/*
 * Copyright (c) 2012 Richard Braun.
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

#ifndef X86_TYPES_H
#define X86_TYPES_H

#ifndef __ASSEMBLER__

#ifdef CONFIG_X86_PAE
  typedef unsigned long long phys_addr_t;
#else
  typedef unsigned long phys_addr_t;
#endif

typedef unsigned long cpu_flags_t;

#endif   // __ASSEMBLER__

#endif
