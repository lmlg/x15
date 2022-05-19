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

#ifndef X86_ELF_H
#define X86_ELF_H

#include <stdint.h>

#define ELF_SHT_SYMTAB   2
#define ELF_SHT_STRTAB   3

struct elf_shdr
{
  uint32_t name;
  uint32_t type;
  uint32_t flags;
  uintptr_t addr;
  uintptr_t offset;
  uint32_t size;
  uint32_t link;
  uint32_t info;
  uint32_t addralign;
  uint32_t entsize;
};

#ifdef __LP64__

struct elf_sym
{
  uint32_t name;
  uint8_t info;
  uint8_t other;
  uint16_t shndx;
  uintptr_t value;
  uintptr_t size;
};

#else

struct elf_sym
{
  uint32_t name;
  uintptr_t value;
  uintptr_t size;
  uint8_t info;
  uint8_t other;
  uint16_t shndx;
};

#endif

#endif
