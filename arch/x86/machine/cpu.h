/*
 * Copyright (c) 2010-2018 Richard Braun.
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

#ifndef X86_CPU_H
#define X86_CPU_H

#include <limits.h>

#include <machine/page.h>
#include <machine/types.h>

// Architecture defined exception vectors.
#define CPU_EXC_DE                  0    // Divide Error.
#define CPU_EXC_DB                  1    // Debug.
#define CPU_EXC_NMI                 2    // NMI Interrupt.
#define CPU_EXC_BP                  3    // Breakpoint.
#define CPU_EXC_OF                  4    // Overflow.
#define CPU_EXC_BR                  5    // BOUND Range Exceeded.
#define CPU_EXC_UD                  6    // Undefined Opcode.
#define CPU_EXC_NM                  7    // No Math Coprocessor.
#define CPU_EXC_DF                  8    // Double Fault.
#define CPU_EXC_TS                  10   // Invalid TSS.
#define CPU_EXC_NP                  11   // Segment Not Present.
#define CPU_EXC_SS                  12   // Stack-Segment Fault.
#define CPU_EXC_GP                  13   // General Protection.
#define CPU_EXC_PF                  14   // Page Fault.
#define CPU_EXC_MF                  16   // Math Fault.
#define CPU_EXC_AC                  17   // Alignment Check.
#define CPU_EXC_MC                  18   // Machine Check.
#define CPU_EXC_XM                  19   // SIMD Floating-Point Exception.

// Exception vectors used for external interrupts.
#define CPU_EXC_INTR_FIRST          32
#define CPU_EXC_INTR_LAST           223

/*
 * System defined exception vectors.
 *
 * The local APIC assigns one priority every 16 vectors.
 */
#define CPU_EXC_XCALL               238
#define CPU_EXC_THREAD_SCHEDULE     239
#define CPU_EXC_HALT                240
#define CPU_EXC_LAPIC_PMC_OF        252
#define CPU_EXC_LAPIC_TIMER         253
#define CPU_EXC_LAPIC_ERROR         254
#define CPU_EXC_LAPIC_SPURIOUS      255

#define CPU_NR_EXC_VECTORS          256

#define CPU_INTR_STACK_SIZE   PAGE_SIZE

#define CPU_VENDOR_STR_SIZE   13
#define CPU_MODEL_NAME_SIZE   49

#define CPU_VENDOR_UNKNOWN   0
#define CPU_VENDOR_INTEL     1
#define CPU_VENDOR_AMD       2

/*
 * L1 cache line size.
 *
 * XXX Use this value until processor selection is available.
 *
 */
#define CPU_L1_SIZE   64

#if CONFIG_MAX_CPUS > 1
  #define __cacheline_aligned   alignas (CPU_L1_SIZE)
#else
  #define __cacheline_aligned
#endif

// CPU word size, 4 or 8 bytes.
#define CPU_WORD_SIZE   (LONG_BIT / 8)

/*
 * Data alignment.
 *
 * This is used to align regions of memory that can store any type of
 * data, such as stacks and sections. The modern i386 as well as the
 * amd64 System V ABIs both mandate 16 byte data alignment. Kernel
 * software could use smaller alignments, but this one is meant to
 * be linked against static libraries, and in particular libgcc, which
 * are built for standard ABIs.
 */
#define CPU_DATA_ALIGN   16

/*
 * Function alignment.
 *
 * Aligning functions improves instruction fetching.
 *
 * Used for assembly functions only.
 *
 * XXX Use this value until processor selection is available.
 */
#define CPU_TEXT_ALIGN   16

// Processor privilege levels.
#define CPU_PL_KERNEL                           0
#define CPU_PL_USER                             3

// Control register 0 flags.
#define CPU_CR0_PE                              0x00000001
#define CPU_CR0_MP                              0x00000002
#define CPU_CR0_TS                              0x00000008
#define CPU_CR0_ET                              0x00000010
#define CPU_CR0_NE                              0x00000020
#define CPU_CR0_WP                              0x00010000
#define CPU_CR0_AM                              0x00040000
#define CPU_CR0_PG                              0x80000000

// Control register 4 flags.
#define CPU_CR4_PSE                             0x00000010
#define CPU_CR4_PAE                             0x00000020
#define CPU_CR4_PGE                             0x00000080

// Model specific registers.
#define CPU_MSR_EFER                            0xc0000080
#define CPU_MSR_FSBASE                          0xc0000100
#define CPU_MSR_GSBASE                          0xc0000101

// EFER MSR flags.
#define CPU_EFER_LME                            0x00000100

// Bit used to make extended CPUID requests.
#define CPU_CPUID_EXT_BIT                       0x80000000

// CPU feature flags as returned by CPUID.
#define CPU_CPUID_BASIC1_EDX_FPU                0x00000001
#define CPU_CPUID_BASIC1_EDX_PSE                0x00000008
#define CPU_CPUID_BASIC1_EDX_PAE                0x00000040
#define CPU_CPUID_BASIC1_EDX_MSR                0x00000020
#define CPU_CPUID_BASIC1_EDX_CX8                0x00000100
#define CPU_CPUID_BASIC1_EDX_APIC               0x00000200
#define CPU_CPUID_BASIC1_EDX_PGE                0x00002000
#define CPU_CPUID_EXT1_EDX_1GP                  0x04000000
#define CPU_CPUID_EXT1_EDX_LM                   0x20000000

// Registers used to implement percpu variables.
#ifdef __LP64__
#  define CPU_LOCAL_REGISTER   "gs"
#else
#  define CPU_LOCAL_REGISTER   "fs"
#endif

#ifndef __ASSEMBLER__

enum cpu_feature
{
  CPU_FEATURE_FPU,
  CPU_FEATURE_PSE,
  CPU_FEATURE_PAE,
  CPU_FEATURE_MSR,
  CPU_FEATURE_CX8,
  CPU_FEATURE_APIC,
  CPU_FEATURE_PGE,
  CPU_FEATURE_1GP,
  CPU_FEATURE_LM,
  CPU_NR_FEATURES
};

#endif

// Exception frame offets.

#ifdef __LP64__
  #define CPU_EXC_FRAME_RAX       0
  #define CPU_EXC_FRAME_RBX       1
  #define CPU_EXC_FRAME_RCX       2
  #define CPU_EXC_FRAME_RDX       3
  #define CPU_EXC_FRAME_RBP       4
  #define CPU_EXC_FRAME_RSI       5
  #define CPU_EXC_FRAME_RDI       6
  #define CPU_EXC_FRAME_R8        7
  #define CPU_EXC_FRAME_R9        8
  #define CPU_EXC_FRAME_R10       9
  #define CPU_EXC_FRAME_R11       10
  #define CPU_EXC_FRAME_R12       11
  #define CPU_EXC_FRAME_R13       12
  #define CPU_EXC_FRAME_R14       13
  #define CPU_EXC_FRAME_R15       14
  #define CPU_EXC_FRAME_VECTOR    15
  #define CPU_EXC_FRAME_ERROR     16
  #define CPU_EXC_FRAME_RIP       17
  #define CPU_EXC_FRAME_CS        18
  #define CPU_EXC_FRAME_RFLAGS    19
  #define CPU_EXC_FRAME_RSP       20
  #define CPU_EXC_FRAME_SS        21
  #define CPU_EXC_FRAME_SIZE      22

  #define CPU_EXC_FRAME_FP        CPU_EXC_FRAME_RBP
  #define CPU_EXC_FRAME_SP        CPU_EXC_FRAME_RSP
  #define CPU_EXC_FRAME_PC        CPU_EXC_FRAME_RIP
  #define CPU_EXC_FRAME_FLAGS     CPU_EXC_FRAME_RFLAGS
#else
  #define CPU_EXC_FRAME_EAX       0
  #define CPU_EXC_FRAME_EBX       1
  #define CPU_EXC_FRAME_ECX       2
  #define CPU_EXC_FRAME_EDX       3
  #define CPU_EXC_FRAME_EBP       4
  #define CPU_EXC_FRAME_ESI       5
  #define CPU_EXC_FRAME_EDI       6
  #define CPU_EXC_FRAME_DS        7
  #define CPU_EXC_FRAME_ES        8
  #define CPU_EXC_FRAME_FS        9
  #define CPU_EXC_FRAME_GS        10
  #define CPU_EXC_FRAME_VECTOR    11
  #define CPU_EXC_FRAME_ERROR     12
  #define CPU_EXC_FRAME_EIP       13
  #define CPU_EXC_FRAME_CS        14
  #define CPU_EXC_FRAME_EFLAGS    15
  #define CPU_EXC_FRAME_ESP       16
  #define CPU_EXC_FRAME_SS        17
  #define CPU_EXC_FRAME_SIZE      18

  #define CPU_EXC_FRAME_FP        CPU_EXC_FRAME_EBP
  #define CPU_EXC_FRAME_SP        CPU_EXC_FRAME_ESP
  #define CPU_EXC_FRAME_PC        CPU_EXC_FRAME_EIP
  #define CPU_EXC_FRAME_FLAGS     CPU_EXC_FRAME_EFLAGS
#endif

// EFLAGS register flags.
#define CPU_EFL_ONE   0x00000002   // Reserved, must be set.
#define CPU_EFL_IF    0x00000200

/*
 * GDT segment selectors.
 *
 * Keep in mind that, on amd64, the size of a GDT entry referred to
 * by a selector depends on the descriptor type.
 */
#define CPU_GDT_SEL_NULL        0
#define CPU_GDT_SEL_CODE        8
#define CPU_GDT_SEL_DATA        16
#define CPU_GDT_SEL_TSS         24

#ifdef __LP64__
  #define CPU_GDT_SIZE            40
#else
  #define CPU_GDT_SEL_DF_TSS      32
  #define CPU_GDT_SEL_PERCPU      40
  #define CPU_GDT_SEL_TLS         48
  #define CPU_GDT_SIZE            56
#endif

#ifndef __ASSEMBLER__

#include <stdalign.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdnoreturn.h>

#include <kern/bitmap.h>
#include <kern/init.h>
#include <kern/macros.h>
#include <kern/percpu.h>

#include <machine/lapic.h>
#include <machine/pit.h>
#include <machine/ssp.h>

struct cpu_tss
{
#ifdef __LP64__
  uint32_t reserved0;
  uint64_t rsp0;
  uint64_t rsp1;
  uint64_t rsp2;
  uint64_t ist[8];
  uint64_t reserved1;
  uint16_t reserved2;
#else
  uint32_t link;
  uint32_t esp0;
  uint32_t ss0;
  uint32_t esp1;
  uint32_t ss1;
  uint32_t esp2;
  uint32_t ss2;
  uint32_t cr3;
  uint32_t eip;
  uint32_t eflags;
  uint32_t eax;
  uint32_t ecx;
  uint32_t edx;
  uint32_t ebx;
  uint32_t esp;
  uint32_t ebp;
  uint32_t esi;
  uint32_t edi;
  uint32_t es;
  uint32_t cs;
  uint32_t ss;
  uint32_t ds;
  uint32_t fs;
  uint32_t gs;
  uint32_t ldt;
  uint16_t trap_bit;
#endif
  uint16_t iobp_base;
} __packed;

// LDT or TSS system segment descriptor.
struct cpu_sysseg_desc
{
  uint32_t word1;
  uint32_t word2;
#ifdef __LP64__
  uint32_t word3;
  uint32_t word4;
#endif
};

struct cpu_gdt
{
  alignas (CPU_L1_SIZE) char descs[CPU_GDT_SIZE];
};

#define CPU_VENDOR_ID_SIZE    13
#define CPU_MODEL_NAME_SIZE   49

struct cpu_feature_map
{
  BITMAP_DECLARE (flags, CPU_NR_FEATURES);
};

struct cpu
{
  uint32_t id;
  uint32_t apic_id;
  char vendor_str[CPU_VENDOR_STR_SIZE];
  char model_name[CPU_MODEL_NAME_SIZE];
  uint32_t cpuid_max_basic;
  uint32_t cpuid_max_extended;
  uint32_t vendor_id;
  uint32_t type;
  uint32_t family;
  uint32_t model;
  uint32_t stepping;
  uint32_t clflush_size;
  uint32_t initial_apic_id;
  struct cpu_feature_map feature_map;
  uint16_t phys_addr_width;
  uint16_t virt_addr_width;
  struct cpu_gdt gdt;

  /*
   * TSS segments, one set per CPU.
   *
   * One TSS at least is required per processor to provide the following :
   *  - stacks for double fault handlers, implemented with task switching
   *    on i386, interrupt stack tables on amd64
   *  - stacks for each privilege level
   *  - I/O permission bitmaps
   *
   * See Intel 64 and IA-32 Architecture Software Developer's Manual,
   * Volume 3 System Programming Guide :
   *  - 6.12.2 Interrupt tasks
   *  - 7.3 Task switching
   */
  struct cpu_tss tss;
#ifndef __LP64__
  struct cpu_tss df_tss;
#endif

  uint32_t started;
  alignas (CPU_DATA_ALIGN) char intr_stack[CPU_INTR_STACK_SIZE];
  alignas (CPU_DATA_ALIGN) char df_stack[CPU_INTR_STACK_SIZE];
};

/*
 * This percpu variable contains the address of the percpu area for the local
 * processor. This is normally the same value stored in the percpu module, but
 * it can be directly accessed through a segment register.
 */
extern void *cpu_local_area;

static inline bool
cpu_feature_map_test (const struct cpu_feature_map *map,
                      enum cpu_feature feature)
{
  return (bitmap_test (map->flags, feature));
}

/*
 * Return the content of the EFLAGS register.
 *
 * Implies a compiler barrier.
 *
 */
static __always_inline cpu_flags_t
cpu_get_eflags (void)
{
  cpu_flags_t eflags;
  asm volatile ("pushf\n"
                "pop %0\n"
                : "=r" (eflags)
                : : "memory");

  return (eflags);
}

#define CPU_INTR_TABLE_SIZE   (CPU_EXC_INTR_LAST - CPU_EXC_INTR_FIRST)

// Gate/segment descriptor bits and masks.
#define CPU_DESC_TYPE_DATA                      0x00000200
#define CPU_DESC_TYPE_CODE                      0x00000a00
#define CPU_DESC_TYPE_TSS                       0x00000900
#define CPU_DESC_TYPE_GATE_INTR                 0x00000e00
#define CPU_DESC_TYPE_GATE_TASK                 0x00000500
#define CPU_DESC_S                              0x00001000
#define CPU_DESC_PRESENT                        0x00008000
#define CPU_DESC_LONG                           0x00200000
#define CPU_DESC_DB                             0x00400000
#define CPU_DESC_GRAN_4KB                       0x00800000

#define CPU_DESC_GATE_OFFSET_LOW_MASK           0x0000ffff
#define CPU_DESC_GATE_OFFSET_HIGH_MASK          0xffff0000
#define CPU_DESC_SEG_IST_MASK                   0x00000007
#define CPU_DESC_SEG_BASE_LOW_MASK              0x0000ffff
#define CPU_DESC_SEG_BASE_MID_MASK              0x00ff0000
#define CPU_DESC_SEG_BASE_HIGH_MASK             0xff000000
#define CPU_DESC_SEG_LIMIT_LOW_MASK             0x0000ffff
#define CPU_DESC_SEG_LIMIT_HIGH_MASK            0x000f0000

// Type for interrupt handler functions.
typedef void (*cpu_intr_handler_fn_t) (uint32_t);

/*
 * TLS segment, as expected by the compiler.
 *
 * TLS isn't actually used inside the kernel. The current purpose of this
 * segment is to implement stack protection.
 *
 * This is a public structure, made available to the boot module so that
 * C code that runs early correctly works when built with stack protection.
 */
struct cpu_tls_seg
{
  uintptr_t unused[SSP_WORD_TLS_OFFSET];
  uintptr_t ssp_guard_word;
};

/*
 * Code or data segment descriptor.
 *
 * See Intel 64 and IA-32 Architecture Software Developer's Manual,
 * Volume 3 System Programming Guide, 3.4.5 Segment Descriptors.
 */
struct cpu_seg_desc
{
  uint32_t low;
  uint32_t high;
};

// Macro to create functions that read/write control registers.
#define CPU_DECL_GETSET_CR(name)   \
static __always_inline uintptr_t   \
CONCAT (cpu_get_, name) (void)   \
{   \
  uintptr_t name;   \
  asm volatile("mov %%" QUOTE (name) ", %0" : "=r" (name) : : "memory");   \
  return (name);   \
}   \
\
static __always_inline void   \
CONCAT (cpu_set_, name) (uintptr_t value)   \
{   \
  asm volatile ("mov %0, %%" QUOTE (name) : : "r" (value) : "memory");   \
}

/*
 * Access to the processor control registers. CR1 is reserved.
 *
 * The caller should assume that these functions are declared as :
 *  static inline uintptr_t cpu_get_crX (void);
 *  static inline void cpu_set_crX (uintptr_t);
 *
 * They all imply a compiler barrier.
 */
CPU_DECL_GETSET_CR (cr0)
CPU_DECL_GETSET_CR (cr2)
CPU_DECL_GETSET_CR (cr3)
CPU_DECL_GETSET_CR (cr4)

/*
 * Enable local interrupts.
 *
 * Implies a compiler barrier.
 */
static __always_inline void
cpu_intr_enable (void)
{
  asm volatile ("sti" : : : "memory");
}

/*
 * Disable local interrupts.
 *
 * Implies a compiler barrier.
 */
static __always_inline void
cpu_intr_disable (void)
{
  asm volatile ("cli" : : : "memory");
}

/*
 * Restore the content of the EFLAGS register, possibly enabling interrupts.
 *
 * Implies a compiler barrier.
 */
static __always_inline void
cpu_intr_restore (cpu_flags_t flags)
{
  asm volatile ("push %0\n"
                "popf\n"
                : : "r" (flags)
                : "memory");
}

/*
 * Disable local interrupts, returning the previous content of the EFLAGS
 * register.
 *
 * Implies a compiler barrier.
 */
static __always_inline void
cpu_intr_save (cpu_flags_t *flags)
{
  *flags = cpu_get_eflags ();
  cpu_intr_disable ();
}

static __always_inline bool
cpu_flags_intr_enabled (cpu_flags_t flags)
{
  return ((flags & CPU_EFL_IF) != 0);
}

/*
 * Return true if interrupts are enabled.
 *
 * Implies a compiler barrier.
 */
static __always_inline bool
cpu_intr_enabled (void)
{
  return (cpu_flags_intr_enabled (cpu_get_eflags ()));
}

// CPU interrupt guard.
static inline void
cpu_intr_guard_fini (void *ptr)
{
  cpu_intr_restore (*(cpu_flags_t *)ptr);
}

#define CPU_INTR_GUARD()   \
  CLEANUP (cpu_intr_guard_fini) cpu_flags_t __unused UNIQ(cig) =   \
    ({   \
       cpu_flags_t flags_;   \
       cpu_intr_save (&flags_);   \
       flags_;   \
     })

/*
 * Spin-wait loop hint.
 *
 * Implies a compiler barrier.
 */
static __always_inline void
cpu_pause (void)
{
  asm volatile ("pause" : : : "memory");
}

/*
 * Make the CPU idle until the next interrupt.
 *
 * Interrupts are enabled. Besides, they're enabled in a way that doesn't
 * allow the processor handling them before entering the idle state if they
 * were disabled before calling this function.
 *
 * Implies a compiler barrier.
 */
static __always_inline void
cpu_idle (void)
{
  asm volatile ("sti; hlt" : : : "memory");
}

/*
 * Halt the CPU.
 *
 * Implies a compiler barrier.
 */
noreturn static __always_inline void
cpu_halt (void)
{
  cpu_intr_disable ();
  while (1)
    asm volatile ("hlt" : : : "memory");
}

/*
 * Halt all other processors.
 *
 * Interrupts must be disabled when calling this function.
 */
void cpu_halt_broadcast (void);

// Generic percpu accessors.

#define cpu_local_ptr(var)   \
MACRO_BEGIN   \
  typeof (var) *ptr_ = &(var);   \
  asm ("add %%" CPU_LOCAL_REGISTER ":%1, %0"   \
       : "+r" (ptr_)   \
       : "m" (cpu_local_area));   \
  ptr_;   \
MACRO_END

#define cpu_local_var(var)   (*cpu_local_ptr(var))

// Generic interrupt-safe percpu accessors.

#define cpu_local_assign(var, val)   \
  asm ("mov %0, %%" CPU_LOCAL_REGISTER ":%1"   \
       : : "r" (val), "m" (var));

#define cpu_local_read(var)   \
MACRO_BEGIN   \
  typeof (var) val_;   \
  asm ("mov %%" CPU_LOCAL_REGISTER ":%1, %0"   \
       : "=r" (val_)   \
       : "m" (var));   \
  val_;   \
MACRO_END

static inline struct cpu*
cpu_current (void)
{
  extern struct cpu cpu_desc;
  return (cpu_local_ptr (cpu_desc));
}

static inline uint32_t
cpu_id (void)
{
  extern struct cpu cpu_desc;
  return (cpu_local_read (cpu_desc.id));
}

static inline uint32_t
cpu_count (void)
{
  extern unsigned int cpu_nr_active;
  return (cpu_nr_active);
}

static inline struct cpu*
cpu_from_id (uint32_t cpu)
{
  extern struct cpu cpu_desc;
  return (percpu_ptr (cpu_desc, cpu));
}

static inline bool
cpu_has_feature (const struct cpu *cpu, enum cpu_feature feature)
{
  return (cpu_feature_map_test (&cpu->feature_map, feature));
}

static __always_inline void
cpu_enable_pse (void)
{
  cpu_set_cr4 (cpu_get_cr4 () | CPU_CR4_PSE);
}

static __always_inline void
cpu_enable_pae (void)
{
  cpu_set_cr4 (cpu_get_cr4 () | CPU_CR4_PAE);
}

static inline int
cpu_has_global_pages (void)
{
  return (cpu_has_feature (cpu_current (), CPU_FEATURE_PGE));
}

/*
 * Enable the use of global pages in the TLB.
 *
 * As a side effect, this function causes a complete TLB flush if global
 * pages were previously disabled.
 *
 * Implies a full memory barrier.
 */
static __always_inline void
cpu_enable_global_pages (void)
{
  cpu_set_cr4 (cpu_get_cr4 () | CPU_CR4_PGE);
}

/*
 * CPUID instruction wrapper.
 *
 * The CPUID instruction is a serializing instruction.
 */
static __always_inline void
cpu_cpuid (uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
  asm volatile ("cpuid" : "+a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)
                : : "memory");
}

static inline void
cpu_get_msr (uint32_t msr, uint32_t *high, uint32_t *low)
{
  asm ("rdmsr" : "=a" (*low), "=d" (*high) : "c" (msr));
}

static inline uint64_t
cpu_get_msr64 (uint32_t msr)
{
  uint32_t high, low;
  cpu_get_msr (msr, &high, &low);
  return (((uint64_t) high << 32) | low);
}

// Implies a full memory barrier.
static inline void
cpu_set_msr (uint32_t msr, uint32_t high, uint32_t low)
{
  asm volatile ("wrmsr" : : "c" (msr), "a" (low), "d" (high) : "memory");
}

// Implies a full memory barrier.
static inline void
cpu_set_msr64 (uint32_t msr, uint64_t value)
{
  uint32_t low = value & 0xffffffff;
  uint32_t high = value >> 32;
  cpu_set_msr (msr, high, low);
}

/*
 * Flush non-global TLB entries.
 *
 * Implies a full memory barrier.
 */
static __always_inline void
cpu_tlb_flush (void)
{
  cpu_set_cr3 (cpu_get_cr3 ());
}

/*
 * Flush all TLB entries, including global ones.
 *
 * Implies a full memory barrier.
 */
static __always_inline void
cpu_tlb_flush_all (void)
{
  if (!cpu_has_global_pages ())
    cpu_tlb_flush ();
  else
    {
      uintptr_t cr4 = cpu_get_cr4 ();

      if (!(cr4 & CPU_CR4_PGE))
        cpu_tlb_flush ();
      else
        {
          cr4 &= ~CPU_CR4_PGE;
          cpu_set_cr4 (cr4);
          cr4 |= CPU_CR4_PGE;
          cpu_set_cr4 (cr4);
        }
    }
}

/*
 * Flush a single page table entry in the TLB.
 *
 * Implies a full memory barrier.
 */
static __always_inline void
cpu_tlb_flush_va (uintptr_t va)
{
  asm volatile ("invlpg (%0)" : : "r" (va) : "memory");
}

static inline uint32_t
cpu_cpuid_max_basic (const struct cpu *cpu)
{
  return (cpu->cpuid_max_basic);
}

static inline uint32_t
cpu_vendor_id (const struct cpu *cpu)
{
  return (cpu->vendor_id);
}

static inline uint32_t
cpu_family (const struct cpu *cpu)
{
  return (cpu->family);
}

static inline uint32_t
cpu_phys_addr_width (const struct cpu *cpu)
{
  return (cpu->phys_addr_width);
}

// Get CPU frequency in Hz.
uint64_t cpu_get_freq (void);

/*
 * Busy-wait for a given amount of time, in microseconds.
 *
 * Implies a compiler barrier.
 */
void cpu_delay (size_t usecs);

// Log processor information.
void cpu_log_info (const struct cpu *cpu);

// Register a local APIC.
void cpu_mp_register_lapic (uint32_t apic_id, bool is_bsp);

/*
 * Start application processors.
 *
 * The x86 architecture uses per-CPU page tables, which are created as a
 * side effect of this function. In order to synchronize their page tables,
 * processors must be able to communicate very soon after calling this
 * function. They communicate through interrupts and threading facilities.
 * On return, physical mappings must not be altered until inter-processor
 * communication is available.
 */
void cpu_mp_setup (void);

// CPU initialization on APs.
void cpu_ap_setup (uint32_t ap_id);

static inline uint32_t
cpu_apic_id (uint32_t cpu)
{
  return (cpu_from_id(cpu)->apic_id);
}

// Send a cross-call interrupt to a remote processor.
static inline void
cpu_send_xcall (uint32_t cpu)
{
  lapic_ipi_send (cpu_apic_id (cpu), CPU_EXC_XCALL);
}

// Send a scheduling interrupt to a remote processor.
static inline void
cpu_send_thread_schedule (uint32_t cpu)
{
  lapic_ipi_send (cpu_apic_id (cpu), CPU_EXC_THREAD_SCHEDULE);
}

/*
 * Register an interrupt handler.
 *
 * This function is only available during system initialization, before the
 * scheduler is started. It is meant for architectural interrupts, including
 * interrupt controllers, and not directly for drivers, which should use
 * the machine-independent intr module instead.
 *
 * Registration is system-wide.
 */
void cpu_register_intr (uint32_t vector, cpu_intr_handler_fn_t fn);

// Clear the interrupt state, set when an exception occurs.

#ifdef __LP64__

static inline void
cpu_clear_intr (void)
{
  uint32_t tmp;

  asm volatile ("mov %%ss, %0\n"
                "pushq %q0\n"
                "pushq %%rsp\n"
                "addq $8, (%%rsp)\n"
                "pushfq\n"
                "mov %%cs, %0\n"
                "pushq %q0\n"
                "pushq $1f\n"
                "iretq\n"
                "1:"
                : "=&r" (tmp) : : "cc", "memory");
  cpu_intr_enable ();
}

#else

static inline void
cpu_clear_intr (void)
{
  asm volatile ("pushfl\n"
                "pushl %%cs\n"
                "pushl $1f\n"
                "iret\n"
                "1:"
                : : : "memory");
  cpu_intr_enable ();
}

#endif

/*
 * CPU fixups, used to safely perform operations on memory that may fault.
 *
 * They work similarly to setjmp/longjmp, with the exception that they
 * are better coupled with exception and traps, since they can use
 * a CPU frame to start the unwinding process.
*/

#ifdef __LP64__
  #define CPU_UNWIND_FRAME_REG   6
  #define CPU_UNWIND_REGISTERS   17
#else
  #define CPU_UNWIND_FRAME_REG   5
  #define CPU_UNWIND_REGISTERS   9
#endif

#define CPU_UNWIND_PC_REG   (CPU_UNWIND_REGISTERS - 1)

// Save the CPU state into an unwind context.
void cpu_unw_mctx_save (uintptr_t *regs);

// Set the CPU context to the unwind context.
noreturn void cpu_unw_mctx_jmp (const uintptr_t *regs, int retval);

// Restore the CPU context from an unwind frame with a return value.
noreturn void cpu_unw_mctx_set_frame (const uintptr_t *regs, int retval);

// Switch to a new stack and PC in a flow's port.
long cpu_port_swap (uintptr_t *args, void *port, void *pc);

// Return from the execution context in a port.
noreturn void cpu_port_return (uintptr_t sp, intptr_t ret);

/*
 * This init operation provides :
 *  - initialization of the BSP structure.
 *  - cpu_delay()
 *  - cpu_local_ptr() and cpu_local_var()
 */
INIT_OP_DECLARE (cpu_setup);

/*
 * This init operation provides :
 *  - cpu_count ()
 *  - access to percpu variables on all processors
 */
INIT_OP_DECLARE (cpu_mp_probe);

/*
 * This init operation provides :
 *  - cpu shutdown operations registered
 */
INIT_OP_DECLARE (cpu_setup_shutdown);

#endif   // __ASSEMBLER__

#endif
