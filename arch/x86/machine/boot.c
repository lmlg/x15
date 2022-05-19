/*
 * Copyright (c) 2010-2017 Richard Braun.
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
 * Early initialization procedure for x86.
 *
 * This module is separated in assembly and C code. The former is where
 * the first instructions are run, and where actions that aren't possible,
 * easy or clean in C are performed.
 *
 * When the boot loader passes control to the kernel, the main processor is
 * in protected mode, paging is disabled, and some boot data are availabe
 * outside the kernel. This module first sets up a basic physical memory
 * allocator so that it can allocate page tables without corrupting the
 * boot data. The .boot section is linked at physical addresses, so that
 * it can run with and without paging enabled. The page tables must properly
 * configure an identity mapping so that this remains true as long as
 * initialization code and data are used. Once the VM system is available,
 * boot data are copied in kernel allocated buffers and their original pages
 * are freed.
 *
 * On amd64, 64-bit code cannot run in legacy or compatibility mode. In order
 * to walk the boot data structures, the kernel must either run 32-bit code
 * (e.g. converting ELF32 to ELF64 objects before linking them) or establish
 * a temporary identity mapping for the first 4 GiB of physical memory. As a
 * way to simplify development, and make it possible to use 64-bit code
 * almost everywhere, the latter solution is implemented (a small part of
 * 32-bit code is required until the identity mapping is in place). Mentions
 * to "enabling paging" do not refer to this initial identity mapping.
 *
 * TODO EFI support.
 */

#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <kern/arg.h>
#include <kern/init.h>
#include <kern/kmem.h>
#include <kern/kernel.h>
#include <kern/log.h>
#include <kern/macros.h>
#include <kern/panic.h>
#include <kern/percpu.h>
#include <kern/thread.h>

#include <machine/acpi.h>
#include <machine/atcons.h>
#include <machine/biosmem.h>
#include <machine/boot.h>
#include <machine/cga.h>
#include <machine/cpu.h>
#include <machine/elf.h>
#include <machine/multiboot.h>
#include <machine/page.h>
#include <machine/pmap.h>
#include <machine/pmu_amd.h>
#include <machine/pmu_intel.h>
#include <machine/uart.h>

#include <vm/kmem.h>

alignas (CPU_DATA_ALIGN) char boot_stack[BOOT_STACK_SIZE] __bootdata;
alignas (CPU_DATA_ALIGN) char boot_ap_stack[BOOT_STACK_SIZE] __bootdata;

#ifdef __LP64__
  alignas (PAGE_SIZE) pmap_pte_t boot_pml4[PMAP_L3_PTES_PER_PT] __bootdata;
  alignas (PAGE_SIZE) pmap_pte_t boot_pdpt[PMAP_L2_PTES_PER_PT] __bootdata;
  alignas (PAGE_SIZE) pmap_pte_t boot_pdir[4 * PMAP_L1_PTES_PER_PT] __bootdata;
  char boot_panic_long_mode_msg[] __bootdata
  = "boot: processor doesn't support long mode";
#endif

struct cpu_tls_seg boot_tls_seg __bootdata =
{
  .ssp_guard_word = SSP_GUARD_WORD,
};

/*
 * This TLS segment descriptor is copied early at boot time into the
 * temporary boot GDT. However, it is incomplete. Assembly code
 * completes it before writing it into the boot GDT before calling
 * any C function, since those may require the TLS segment ready if
 * stack protection is enabled.
 */
struct cpu_seg_desc boot_tls_seg_desc __bootdata =
{
  .low = (sizeof (boot_tls_seg) & 0xffff),
  .high = CPU_DESC_DB | ((sizeof (boot_tls_seg) >> 16) & 0xf) |
          CPU_DESC_PRESENT | CPU_DESC_S | CPU_DESC_TYPE_DATA,
};

// Copies of the multiboot data passed by the boot loader.
static struct multiboot_raw_info boot_raw_mbi __bootdata;
static struct multiboot_info boot_mbi __initdata;

static char boot_tmp_cmdline[ARG_CMDLINE_MAX_SIZE] __bootdata;

static char boot_panic_intro_msg[] __bootdata = "panic: ";
static char boot_panic_loader_msg[] __bootdata
  = "boot: not started by a multiboot compliant boot loader";
static char boot_panic_meminfo_msg[] __bootdata
  = "boot: missing basic memory information";
static char boot_panic_cmdline_msg[] __bootdata
  = "boot: command line too long";

static volatile unsigned int boot_ap_id __bootdata;
static char *boot_ap_stacks[CONFIG_MAX_CPUS - 1] __initdata;

pmap_pte_t * boot_ap_setup (void);
char * boot_get_ap_stack (void);

void* __boot
boot_memcpy (void *dest, const void *src, size_t n)
{
  for (size_t i = 0; i < n; ++i)
    ((char *)dest)[i] = ((const char *)src)[i];

  return (dest);
}

void* __boot
boot_memmove (void *dest, const void *src, size_t n)
{
  if (dest <= src)
    return (boot_memcpy (dest, src, n));

  char *dest_ptr = (char *)dest + n;
  const char *src_ptr = (const char *)src + n;

  for (size_t i = 0; i < n; ++i)
    *--dest_ptr = *--src_ptr;

  return (dest);
}

void* __boot
boot_memset (void *s, int c, size_t n)
{
  for (size_t i = 0; i < n; ++i)
    ((char *)s)[i] = c;

  return (s);
}

size_t __boot
boot_strlen (const char *s)
{
  const char *start = s;
  for (; *s; ++s)
    ;

  return (s - start);
}

void __boot
boot_panic (const char *msg)
{
  uint16_t *ptr = (uint16_t *)BOOT_CGAMEM,
           *end = ptr + BOOT_CGACHARS;
  const char *s = boot_panic_intro_msg;

  for (; ptr < end && *s; ++s)
    *ptr++ = (BOOT_CGACOLOR << 8) | *s;

  for (s = msg; ptr < end && *s; ++s)
    *ptr++ = (BOOT_CGACOLOR << 8) | *s;

  while (ptr < end)
    *ptr++ = (BOOT_CGACOLOR << 8) | ' ';

  cpu_halt ();
  __builtin_unreachable ();
}

static void __boot
boot_save_mod_cmdline_sizes (struct multiboot_raw_info *mbi)
{
  if (mbi->flags & MULTIBOOT_LOADER_MODULES)
    {
      uintptr_t addr = mbi->mods_addr;

      for (uint32_t i = 0; i < mbi->mods_count; i++)
        {
          _Auto mod = (struct multiboot_raw_module *)addr + i;
          mod->reserved = boot_strlen ((char *)(uintptr_t)mod->string) + 1;
        }
    }
}

static void __boot
boot_register_data (const struct multiboot_raw_info *mbi)
{
  biosmem_register_boot_data ((uintptr_t)&_boot,
                              BOOT_VTOP ((uintptr_t)&_end), false);

  if (mbi->flags & MULTIBOOT_LOADER_MODULES)
    {
      uint32_t i = mbi->mods_count * sizeof (struct multiboot_raw_module);
      biosmem_register_boot_data (mbi->mods_addr, mbi->mods_addr + i, true);

      uintptr_t tmp = mbi->mods_addr;

      for (i = 0; i < mbi->mods_count; i++)
        {
          _Auto mod = (struct multiboot_raw_module *)tmp + i;
          biosmem_register_boot_data (mod->mod_start, mod->mod_end, true);

          if (mod->string)
            biosmem_register_boot_data (mod->string,
                                        mod->string + mod->reserved, true);
        }
    }

  if (mbi->flags & MULTIBOOT_LOADER_SHDR)
    {
      uintptr_t tmp = mbi->shdr_num * mbi->shdr_size;
      biosmem_register_boot_data (mbi->shdr_addr, mbi->shdr_addr + tmp, true);

      tmp = mbi->shdr_addr;

      for (uint32_t i = 0; i < mbi->shdr_num; i++)
        {
          _Auto shdr = (struct elf_shdr *)(tmp + i * mbi->shdr_size);
          if (shdr->type != ELF_SHT_SYMTAB && shdr->type != ELF_SHT_STRTAB)
            continue;

          biosmem_register_boot_data (shdr->addr,
                                      shdr->addr + shdr->size, true);
        }
    }
}

pmap_pte_t* __boot
boot_setup_paging (struct multiboot_raw_info *mbi, unsigned long eax)
{
  if (eax != MULTIBOOT_LOADER_MAGIC)
    boot_panic (boot_panic_loader_msg);

  if (!(mbi->flags & MULTIBOOT_LOADER_MEMORY))
    boot_panic (boot_panic_meminfo_msg);

  /*
   * Save the multiboot data passed by the boot loader, initialize the
   * bootstrap allocator and set up paging.
   */
  boot_memmove (&boot_raw_mbi, mbi, sizeof (boot_raw_mbi));

  /*
   * The kernel command line must be passed as early as possible to the
   * arg module so that other modules can look up options. Instead of
   * mapping it later, make a temporary copy.
   */
  if (!(mbi->flags & MULTIBOOT_LOADER_CMDLINE))
    boot_tmp_cmdline[0] = '\0';
  else
    {
      uintptr_t addr = mbi->cmdline;
      size_t length = boot_strlen ((const char *) addr) + 1;

      if (length > ARRAY_SIZE (boot_tmp_cmdline))
        boot_panic (boot_panic_cmdline_msg);

      boot_memcpy (boot_tmp_cmdline, (const char *)addr, length);
    }

  if ((mbi->flags & MULTIBOOT_LOADER_MODULES) && !mbi->mods_count)
    boot_raw_mbi.flags &= ~MULTIBOOT_LOADER_MODULES;

  /*
   * The module command lines will be memory mapped later during
   * initialization. Their respective sizes must be saved.
   */
  boot_save_mod_cmdline_sizes (&boot_raw_mbi);
  boot_register_data (&boot_raw_mbi);
  biosmem_bootstrap (&boot_raw_mbi);
  return (pmap_setup_paging ());
}

#ifdef CONFIG_X86_PAE
  #define BOOT_PAE_LABEL " PAE"
#else
  #define BOOT_PAE_LABEL
#endif

void __init
boot_log_info (void)
{
  log_info (KERNEL_NAME "/" CONFIG_SUBARCH " " KERNEL_VERSION
            BOOT_PAE_LABEL);
}

static void* __init
boot_save_memory (uint32_t addr, size_t size)
{
  /*
   * Creates temporary virtual mappings because, on 32-bits systems,
   * there is no guarantee that the boot data will be available from
   * the direct physical mapping.
   */
  uintptr_t map_addr;
  size_t map_size;
  const void *src = vm_kmem_map_pa (addr, size, &map_addr, &map_size);

  if (! src)
    panic ("boot: unable to map boot data in kernel map");

  void *copy = kmem_alloc (size);
  if (! copy)
    panic ("boot: unable to allocate memory for boot data copy");

  memcpy (copy, src, size);
  vm_kmem_unmap_pa (map_addr, map_size);
  return (copy);
}

static void __init
boot_save_mod (struct multiboot_module *dest_mod,
               const struct multiboot_raw_module *src_mod)
{
  size_t map_size, size = src_mod->mod_end - src_mod->mod_start;
  uintptr_t map_addr;
  const void *src = vm_kmem_map_pa (src_mod->mod_start, size,
                                    &map_addr, &map_size);

  if (! src)
    panic ("boot: unable to map module in kernel map");

  void *copy = kmem_alloc (size);
  if (! copy)
    panic ("boot: unable to allocate memory for module copy");

  memcpy (copy, src, size);
  vm_kmem_unmap_pa (map_addr, map_size);

  dest_mod->mod_start = copy;
  dest_mod->mod_end = copy + size;
  dest_mod->string = !src_mod->string ?
                     0 : boot_save_memory (src_mod->string, src_mod->reserved);
}

static void __init
boot_save_mods (void)
{
  if (!(boot_raw_mbi.flags & MULTIBOOT_LOADER_MODULES))
    {
      boot_mbi.mods_addr = NULL;
      boot_mbi.mods_count = boot_raw_mbi.mods_count;
      return;
    }

  size_t map_size,
         size = boot_raw_mbi.mods_count * sizeof (struct multiboot_raw_module);
  uintptr_t map_addr;
  const struct multiboot_raw_module *src =
    vm_kmem_map_pa (boot_raw_mbi.mods_addr, size, &map_addr, &map_size);

  if (! src)
    panic ("boot: unable to map module table in kernel map");

  size = boot_raw_mbi.mods_count * sizeof (struct multiboot_module);
  struct multiboot_module *dest = kmem_alloc (size);

  if (! dest)
    panic ("boot: unable to allocate memory for the module table");

  for (uint32_t i = 0; i < boot_raw_mbi.mods_count; i++)
    boot_save_mod (&dest[i], &src[i]);

  vm_kmem_unmap_pa (map_addr, map_size);

  boot_mbi.mods_addr = dest;
  boot_mbi.mods_count = boot_raw_mbi.mods_count;
}

/*
 * Copy boot data in kernel allocated memory.
 *
 * At this point, the only required boot data are the modules and the command
 * line strings. Optionally, the kernel can use the symbol table, if passed by
 * the boot loader. Once the boot data are managed as kernel buffers, their
 * backing pages can be freed.
 */
static int __init
boot_save_data (void)
{
  boot_mbi.flags = boot_raw_mbi.flags;
  boot_save_mods ();
  return (0);
}

INIT_OP_DEFINE (boot_save_data,
                INIT_OP_DEP (kmem_setup, true),
                INIT_OP_DEP (vm_kmem_setup, true));

void __init
boot_main (void)
{
  arg_set_cmdline (boot_tmp_cmdline);
  kernel_main ();
  __builtin_unreachable ();
}

void __init
boot_alloc_ap_stacks (void)
{
  for (uint32_t i = 1; i < cpu_count (); i++)
    {
      char *stack = kmem_alloc (BOOT_STACK_SIZE);
      if (! stack)
        panic ("boot: unable to allocate stack for cpu%u", i);

      boot_ap_stacks[i - 1] = stack;
    }
}

void __init
boot_set_ap_id (uint32_t ap_id)
{
  boot_ap_id = ap_id;
}

pmap_pte_t* __boot
boot_ap_setup (void)
{
  return (pmap_ap_setup_paging (boot_ap_id));
}

char* __init
boot_get_ap_stack (void)
{
  uint32_t index = boot_ap_id - 1;

  /*
   * TODO Remove this check once all the SMP-related code has been cleanly
   * isolated.
   */
#if CONFIG_SMP
  assert (index < ARRAY_SIZE (boot_ap_stacks));
#endif

  return (boot_ap_stacks[index]);
}

void __init
boot_ap_main (void)
{
  cpu_ap_setup (boot_ap_id);
  thread_ap_setup ();
  pmap_ap_setup ();
  percpu_ap_setup ();
  kernel_ap_main ();

  __builtin_unreachable ();
}

// Init operation aliases.

static int __init
boot_bootstrap_console (void)
{
  return (0);
}

INIT_OP_DEFINE (boot_bootstrap_console,
                INIT_OP_DEP (atcons_bootstrap, true),
                INIT_OP_DEP (uart_bootstrap, true));

static int __init
boot_setup_console (void)
{
  return (0);
}

INIT_OP_DEFINE (boot_setup_console,
                INIT_OP_DEP (atcons_setup, true),
                INIT_OP_DEP (uart_setup, true));

static int __init
boot_load_vm_page_zones (void)
{
  return (0);
}

INIT_OP_DEFINE (boot_load_vm_page_zones,
                INIT_OP_DEP (biosmem_setup, true));

static int __init
boot_setup_intr (void)
{
  return (0);
}

INIT_OP_DEFINE (boot_setup_intr,
                INIT_OP_DEP (acpi_setup, true));

#ifdef CONFIG_PERFMON

static int __init
boot_setup_pmu (void)
{
  return (0);
}

#ifdef CONFIG_X86_PMU_AMD
  #define BOOT_PMU_AMD_INIT_OP_DEPS   INIT_OP_DEP (pmu_amd_setup, false),
#else
  #define BOOT_PMU_AMD_INIT_OP_DEPS
#endif

#ifdef CONFIG_X86_PMU_INTEL
  #define BOOT_PMU_INTEL_INIT_OP_DEPS   INIT_OP_DEP (pmu_intel_setup, false),
#else
  #define BOOT_PMU_INTEL_INIT_OP_DEPS
#endif

INIT_OP_DEFINE (boot_setup_pmu,
                BOOT_PMU_AMD_INIT_OP_DEPS
                BOOT_PMU_INTEL_INIT_OP_DEPS);
#endif

static int __init
boot_setup_shutdown (void)
{
  return (0);
}

INIT_OP_DEFINE (boot_setup_shutdown,
                INIT_OP_DEP (acpi_setup, true),
                INIT_OP_DEP (cpu_setup_shutdown, true));
