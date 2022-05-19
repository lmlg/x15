/*
 * Copyright (c) 2013 Richard Braun.
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

#ifndef VM_DEFS_H
#define VM_DEFS_H

// Advice values.
#define VM_ADV_NORMAL       0
#define VM_ADV_RANDOM       1
#define VM_ADV_SEQUENTIAL   2
#define VM_ADV_WILLNEED     3
#define VM_ADV_DONTNEED     4
#define VM_ADV_DEFAULT      VM_ADV_NORMAL

// Inheritance values.
#define VM_INHERIT_NONE       0
#define VM_INHERIT_SHARE      1
#define VM_INHERIT_COPY       2
#define VM_INHERIT_DEFAULT    VM_INHERIT_COPY

// Protection flags.
#define VM_PROT_NONE      0
#define VM_PROT_READ      1
#define VM_PROT_WRITE     2
#define VM_PROT_EXECUTE   4
#define VM_PROT_DEFAULT   (VM_PROT_READ | VM_PROT_WRITE)
#define VM_PROT_ALL   \
  (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE)

#endif
