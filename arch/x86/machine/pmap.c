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
 * TODO Review locking.
 */

#include <assert.h>
#include <errno.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <kern/cpumap.h>
#include <kern/init.h>
#include <kern/kmem.h>
#include <kern/list.h>
#include <kern/log.h>
#include <kern/macros.h>
#include <kern/mutex.h>
#include <kern/panic.h>
#include <kern/percpu.h>
#include <kern/spinlock.h>
#include <kern/syscnt.h>
#include <kern/thread.h>

#include <machine/biosmem.h>
#include <machine/boot.h>
#include <machine/cpu.h>
#include <machine/page.h>
#include <machine/pmap.h>
#include <machine/tcb.h>
#include <machine/types.h>

#include <vm/defs.h>
#include <vm/kmem.h>
#include <vm/page.h>

// Properties of a page translation level.
struct pmap_pt_level
{
  uint32_t skip;
  uint32_t bits;
  uint32_t ptes_per_pt;
  pmap_pte_t mask;
};

// Table of page translation properties.
static struct pmap_pt_level pmap_pt_levels[] __read_mostly =
{
  { PMAP_L0_SKIP, PMAP_L0_BITS, PMAP_L0_PTES_PER_PT, PMAP_L0_MASK },
  { PMAP_L1_SKIP, PMAP_L1_BITS, PMAP_L1_PTES_PER_PT, PMAP_L1_MASK },
#if PMAP_NR_LEVELS > 2
  { PMAP_L2_SKIP, PMAP_L2_BITS, PMAP_L2_PTES_PER_PT, PMAP_L2_MASK },
  #if PMAP_NR_LEVELS > 3
  { PMAP_L3_SKIP, PMAP_L3_BITS, PMAP_L3_PTES_PER_PT, PMAP_L3_MASK },
  #endif
#endif
};

// Per-CPU page tables.
struct pmap_cpu_table
{
  struct list node;
  phys_addr_t root_ptp_pa;
};

struct pmap
{
  struct pmap_cpu_table *cpu_tables[CONFIG_MAX_CPUS];
};

/*
 * Type for page table walking functions.
 *
 * See pmap_walk_vas().
 */
typedef void (*pmap_walk_fn_t) (phys_addr_t, uint32_t, uint32_t);

/*
 * The kernel per-CPU page tables are used early enough during bootstrap
 * that using a percpu variable would actually become ugly. This array
 * is rather small anyway.
 */
static struct pmap_cpu_table pmap_kernel_cpu_tables[CONFIG_MAX_CPUS] __read_mostly;

struct pmap pmap_kernel_pmap;
struct pmap *pmap_current_ptr __percpu;

#ifdef CONFIG_X86_PAE

  // Alignment required on page directory pointer tables.
  #define PMAP_PDPT_ALIGN 32

  // Hidden" kernel root page tables for PAE mode.
  static alignas (PMAP_PDPT_ALIGN) pmap_pte_t
  pmap_cpu_kpdpts[CONFIG_MAX_CPUS][PMAP_L2_PTES_PER_PT] __read_mostly;

#endif

// Flags related to page protection.
#define PMAP_PTE_PROT_MASK   PMAP_PTE_RW

/*
 * Table used to convert machine independent protection flags to architecture
 * specific PTE bits.
 */
static pmap_pte_t pmap_prot_table[VM_PROT_ALL + 1] __read_mostly;

// Structures related to inter-processor page table updates.

#define PMAP_UPDATE_OP_ENTER     1
#define PMAP_UPDATE_OP_REMOVE    2
#define PMAP_UPDATE_OP_PROTECT   3

struct pmap_update_enter_args
{
  uintptr_t va;
  phys_addr_t pa;
  int prot;
  int flags;
};

struct pmap_update_remove_args
{
  uintptr_t start;
  uintptr_t end;
};

struct pmap_update_protect_args
{
  uintptr_t start;
  uintptr_t end;
  int prot;
};

struct pmap_update_op
{
  struct cpumap cpumap;
  uint32_t operation;

  union
    {
      struct pmap_update_enter_args enter_args;
      struct pmap_update_remove_args remove_args;
      struct pmap_update_protect_args protect_args;
    };
};

/*
 * Maximum number of operations that can be batched before an implicit
 * update.
 */
#define PMAP_UPDATE_MAX_OPS   32

/*
 * List of update operations.
 *
 * A list of update operations is a container of operations that are pending
 * for a pmap. Updating can be implicit, e.g. when a list has reached its
 * maximum size, or explicit, when pmap_update() is called. Operation lists
 * are thread-local objects.
 *
 * The cpumap is the union of all processors affected by at least one
 * operation.
 */
struct pmap_update_oplist
{
  alignas (CPU_L1_SIZE) struct cpumap cpumap;
  struct pmap *pmap;
  uint32_t nr_ops;
  struct pmap_update_op ops[PMAP_UPDATE_MAX_OPS];
};

// Statically allocated data for the main booter thread.
static struct cpumap pmap_booter_cpumap __initdata;
static struct pmap_update_oplist pmap_booter_oplist __initdata;

// Each regular thread gets an operation list from this cache.
static struct kmem_cache pmap_update_oplist_cache;

// Queue holding update requests from remote processors.
struct pmap_update_queue
{
  struct spinlock lock;
  struct list requests;
};

/*
 * Syncer thread.
 *
 * There is one such thread per processor. They are the recipients of
 * update requests, providing thread context for the mapping operations
 * they perform.
 */
struct pmap_syncer
{
  alignas (CPU_L1_SIZE) struct thread *thread;
  struct pmap_update_queue queue;
  struct syscnt sc_updates;
  struct syscnt sc_update_enters;
  struct syscnt sc_update_removes;
  struct syscnt sc_update_protects;
};

static void pmap_sync (void *arg);

static struct pmap_syncer pmap_syncer __percpu;

/*
 * Maximum number of mappings for which individual TLB invalidations can be
 * performed. Global TLB flushes are done beyond this value.
 */
#define PMAP_UPDATE_MAX_MAPPINGS   64

/*
 * Per processor request, queued on a remote processor.
 *
 * The number of mappings is used to determine whether it's best to flush
 * individual TLB entries or globally flush the TLB.
 */
struct pmap_update_request
{
  alignas (CPU_L1_SIZE) struct list node;
  struct spinlock lock;
  struct thread *sender;
  const struct pmap_update_oplist *oplist;
  unsigned int nr_mappings;
  int done;
  int error;
};

/*
 * Per processor array of requests.
 *
 * When an operation list is to be applied, the thread triggering the update
 * acquires the processor-local array of requests and uses it to queue requests
 * on remote processors.
 */
struct pmap_update_request_array
{
  struct pmap_update_request requests[CONFIG_MAX_CPUS];
  struct mutex lock;
};

static struct pmap_update_request_array pmap_update_request_array __percpu;

static int pmap_do_remote_updates __read_mostly;

static struct kmem_cache pmap_cache;

#ifdef CONFIG_X86_PAE
  static char pmap_panic_no_pae[] __bootdata
  = "pmap: PAE not supported";
#endif

static char pmap_panic_inval_msg[] __bootdata
  = "pmap: invalid physical address";
static char pmap_panic_directmap_msg[] __bootdata
  = "pmap: invalid direct physical mapping";

static __always_inline size_t
pmap_pte_index (uintptr_t va, const struct pmap_pt_level *pt_level)
{
  return ((va >> pt_level->skip) & ((1UL << pt_level->bits) - 1));
}

static void __boot
pmap_boot_enter (pmap_pte_t *root_ptp, uintptr_t va, phys_addr_t pa,
                 size_t pgsize)
{
  if (pa != (pa & PMAP_PA_MASK))
    boot_panic (pmap_panic_inval_msg);

  pmap_pte_t bits;
  uint32_t last_level;

  switch (pgsize)
    {
#ifdef __LP64__
      case (1 << PMAP_L2_SKIP):
        bits = PMAP_PTE_PS;
        last_level = 2;
        break;
#endif
      case (1 << PMAP_L1_SKIP):
        bits = PMAP_PTE_PS;
        last_level = 1;
        break;
      default:
        bits = 0;
        last_level = 0;
    }

  const struct pmap_pt_level *pt_levels =
    (void *)BOOT_VTOP ((uintptr_t) pmap_pt_levels);
  pmap_pte_t *pt = root_ptp;

  for (uint32_t level = PMAP_NR_LEVELS - 1; level != last_level; level--)
    {
      _Auto pt_level = &pt_levels[level];
      _Auto pte = &pt[pmap_pte_index (va, pt_level)];
      pmap_pte_t *ptp;

      if (*pte)
        ptp = (void *)(uintptr_t)(*pte & PMAP_PA_MASK);
      else
        {
          ptp = biosmem_bootalloc (1);
          *pte = ((uintptr_t)ptp | PMAP_PTE_RW | PMAP_PTE_P) & pt_level->mask;
        }

      pt = ptp;
    }

  _Auto pt_level = &pt_levels[last_level];
  pt[pmap_pte_index (va, pt_level)] = (pa & PMAP_PA_MASK) |
                                      PMAP_PTE_RW | PMAP_PTE_P | bits;
}

static unsigned long __boot
pmap_boot_get_pgsize (void)
{
  uint32_t eax, ebx, ecx, edx;

#ifdef __LP64__
  eax = CPU_CPUID_EXT_BIT;
  cpu_cpuid (&eax, &ebx, &ecx, &edx);

  if (eax <= CPU_CPUID_EXT_BIT)
    goto out;

  eax = (CPU_CPUID_EXT_BIT | 1);
  cpu_cpuid (&eax, &ebx, &ecx, &edx);

  if (edx & CPU_CPUID_EXT1_EDX_1GP)
    return (1 << PMAP_L2_SKIP);

out:
  return (1 << PMAP_L1_SKIP);
#else
  eax = 0;
  cpu_cpuid (&eax, &ebx, &ecx, &edx);

  if (eax == 0)
    goto out;

  eax = 1;
  cpu_cpuid (&eax, &ebx, &ecx, &edx);

#ifdef CONFIG_X86_PAE
  if (!(edx & CPU_CPUID_BASIC1_EDX_PAE))
    boot_panic (pmap_panic_no_pae);

  return (1 << PMAP_L1_SKIP);
#else
  if (edx & CPU_CPUID_BASIC1_EDX_PSE)
    return (1 << PMAP_L1_SKIP);
#endif

out:
  return (PAGE_SIZE);
#endif
}

#ifdef __LP64__
  #define pmap_boot_enable_pgext(pgsize)   ((void)(pgsize))
#else

static void __boot
pmap_boot_enable_pgext (unsigned long pgsize)
{
  if (pgsize == PAGE_SIZE)
    return;

  /*
   * On 64-bits systems, PAE is already enabled.
   *
   * See the boot module.
   */
#ifdef CONFIG_X86_PAE
  cpu_enable_pae ();
#else
  cpu_enable_pse ();
#endif
}
#endif

pmap_pte_t* __boot
pmap_setup_paging (void)
{
  // Use large pages for the direct physical mapping when possible.
  size_t pgsize = pmap_boot_get_pgsize ();
  pmap_boot_enable_pgext (pgsize);

  /*
   * Create the initial mappings. The first is for the .boot section
   * and acts as the mandatory identity mapping. The second is the
   * direct physical mapping of physical memory.
   */

  pmap_pte_t *root_ptp =
#ifdef CONFIG_X86_PAE
    (void *) BOOT_VTOP ((uintptr_t) pmap_cpu_kpdpts[0]);
#else
    biosmem_bootalloc (1);
#endif

  uintptr_t va = vm_page_trunc ((uintptr_t)&_boot);
  phys_addr_t pa = va;
  size_t size = vm_page_round ((uintptr_t) &_boot_end) - va;

  for (size_t i = 0; i < size; i += PAGE_SIZE)
    {
      pmap_boot_enter (root_ptp, va, pa, PAGE_SIZE);
      va += PAGE_SIZE;
      pa += PAGE_SIZE;
    }

  phys_addr_t directmap_end = biosmem_directmap_end ();

  if (directmap_end >
      PMAP_END_DIRECTMAP_ADDRESS - PMAP_START_DIRECTMAP_ADDRESS)
    boot_panic (pmap_panic_directmap_msg);

  va = PMAP_START_DIRECTMAP_ADDRESS;
  pa = 0;

  for (size_t i = 0; i < directmap_end; i += pgsize)
    {
      pmap_boot_enter (root_ptp, va, pa, pgsize);
      va += pgsize;
      pa += pgsize;
    }

#ifdef __LP64__
  /*
   * On 64-bits systems, the kernel isn't linked at addresses included
   * in the direct mapping, which requires the creation of an additional
   * mapping for it.
   */
  va = P2ALIGN ((uintptr_t)&_init, pgsize);
  pa = BOOT_VTOP (va);
  size = vm_page_round ((uintptr_t)&_end) - va;

  for (size_t i = 0; i < size; i += pgsize)
    {
      pmap_boot_enter (root_ptp, va, pa, pgsize);
      va += pgsize;
      pa += pgsize;
    }
#endif

  struct pmap_cpu_table *cpu_table =
    (void *)BOOT_VTOP ((uintptr_t)&pmap_kernel_cpu_tables[0]);
  cpu_table->root_ptp_pa = (uintptr_t)root_ptp;

  return (root_ptp);
}

pmap_pte_t* __boot
pmap_ap_setup_paging (uint32_t ap_id)
{
  size_t pgsize = pmap_boot_get_pgsize ();
  pmap_boot_enable_pgext (pgsize);

  struct pmap *pmap = (void *)BOOT_VTOP ((uintptr_t)&pmap_kernel_pmap);
  struct pmap_cpu_table *cpu_table =
    (void *)BOOT_VTOP((uintptr_t) pmap->cpu_tables[ap_id]);

#ifdef CONFIG_X86_PAE
  return ((void *)(uint32_t)cpu_table->root_ptp_pa);
#else
  return ((void *)cpu_table->root_ptp_pa);
#endif
}

static bool
pmap_range_valid (const struct pmap *pmap, uintptr_t start, uintptr_t end)
{
  return (start < end &&
          (end <= PMAP_START_DIRECTMAP_ADDRESS ||
           start >= PMAP_END_DIRECTMAP_ADDRESS) &&
          (pmap == pmap_get_kernel_pmap () ?
           (start >= PMAP_START_KMEM_ADDRESS &&
            end <= PMAP_END_KMEM_ADDRESS) :
           (end <= PMAP_END_ADDRESS)));
}

static inline pmap_pte_t*
pmap_ptp_from_pa (phys_addr_t pa)
{
  return ((pmap_pte_t *)(uintptr_t)vm_page_direct_va (pa));
}

static void
pmap_ptp_clear (pmap_pte_t *ptp)
{
  memset (ptp, 0, PAGE_SIZE);
}

static inline void
pmap_pte_set (pmap_pte_t *pte, phys_addr_t pa, pmap_pte_t pte_bits,
              const struct pmap_pt_level *pt_level)
{
  *pte = ((pa & PMAP_PA_MASK) | PMAP_PTE_P | pte_bits) & pt_level->mask;
}

static inline void
pmap_pte_clear (pmap_pte_t *pte)
{
  *pte = 0;
}

static inline int
pmap_pte_valid (pmap_pte_t pte)
{
  return (pte != 0);
}

static inline int
pmap_pte_large (pmap_pte_t pte)
{
  return ((pte & PMAP_PTE_PS) != 0);
}

static inline pmap_pte_t*
pmap_pte_next (pmap_pte_t pte)
{
  assert (pmap_pte_valid (pte));
  return (pmap_ptp_from_pa (pte & PMAP_PA_MASK));
}

/*
 * Helper function for initialization procedures that require post-fixing
 * page properties.
 */
static void __init
pmap_walk_vas (uintptr_t start, uintptr_t end, pmap_walk_fn_t walk_fn)
{
  assert (vm_page_aligned (start));
  assert (start < end);
#ifdef __LP64__
  assert (start < PMAP_END_ADDRESS || start >= PMAP_START_KERNEL_ADDRESS);
#endif

  uintptr_t va = start;
  phys_addr_t root_ptp_pa =
    pmap_get_kernel_pmap()->cpu_tables[cpu_id ()]->root_ptp_pa;

  do
    {
#ifdef __LP64__
      // Handle long mode canonical form.
      if (va == PMAP_END_ADDRESS)
        va = PMAP_START_KERNEL_ADDRESS;
#endif

      uint32_t level = PMAP_NR_LEVELS - 1;
      phys_addr_t ptp_pa = root_ptp_pa;
      pmap_pte_t *ptp = pmap_ptp_from_pa (ptp_pa);

      const struct pmap_pt_level *pt_level;
      while (1)
        {
          pt_level = &pmap_pt_levels[level];
          uint32_t index = pmap_pte_index (va, pt_level);
          _Auto pte = &ptp[index];

          if (!pmap_pte_valid (*pte))
            break;

          walk_fn (ptp_pa, index, level);
          if (!level || pmap_pte_large (*pte))
            break;

          --level;
          ptp_pa = *pte & PMAP_PA_MASK;
          ptp = pmap_ptp_from_pa (ptp_pa);
        }

      va = P2END (va, 1UL << pt_level->skip);
    }
  while (va > start && va < end);
}

static void __init
pmap_setup_global_page (phys_addr_t ptp_pa, uint32_t index, uint32_t level)
{
  pmap_pte_t *pte = &pmap_ptp_from_pa(ptp_pa)[index];
  if (!level || pmap_pte_large (*pte))
    *pte |= PMAP_PTE_G;
}

static void __init
pmap_setup_global_pages (void)
{
  pmap_walk_vas (PMAP_START_KERNEL_ADDRESS, PMAP_END_KERNEL_ADDRESS,
                 pmap_setup_global_page);
  pmap_pt_levels[0].mask |= PMAP_PTE_G;
  cpu_enable_global_pages ();
}

static void
pmap_update_oplist_ctor (void *arg)
{
  struct pmap_update_oplist *oplist = arg;
  cpumap_zero (&oplist->cpumap);
  oplist->pmap = NULL;
  oplist->nr_ops = 0;
}

static int
pmap_update_oplist_create (struct pmap_update_oplist **oplistp)
{
  struct pmap_update_oplist *oplist =
    kmem_cache_alloc (&pmap_update_oplist_cache);

  if (! oplist)
    return (ENOMEM);

  *oplistp = oplist;
  return (0);
}

static void
pmap_update_oplist_destroy (struct pmap_update_oplist *oplist)
{
  kmem_cache_free (&pmap_update_oplist_cache, oplist);
}

static struct pmap_update_oplist*
pmap_update_oplist_get (void)
{
  struct pmap_update_oplist *oplist =
    tcb_get_pmap_update_oplist (tcb_current ());
  assert (oplist != NULL);
  return (oplist);
}

static int
pmap_update_oplist_prepare (struct pmap_update_oplist *oplist,
                            struct pmap *pmap)
{
  if (oplist->pmap != pmap)
    {
      assert (!oplist->pmap);
      oplist->pmap = pmap;
    }
  else if (oplist->nr_ops == ARRAY_SIZE (oplist->ops))
    {
      int error = pmap_update (pmap);
      oplist->pmap = pmap;
      return (error);
    }

  return (0);
}

static struct pmap_update_op*
pmap_update_oplist_prev_op (struct pmap_update_oplist *oplist)
{
  return (oplist->nr_ops ? &oplist->ops[oplist->nr_ops - 1] : NULL);
}

static struct pmap_update_op*
pmap_update_oplist_prepare_op (struct pmap_update_oplist *oplist)
{
  assert (oplist->nr_ops < ARRAY_SIZE (oplist->ops));
  return (&oplist->ops[oplist->nr_ops]);
}

static void
pmap_update_oplist_finish_op (struct pmap_update_oplist *oplist)
{
  assert (oplist->nr_ops < ARRAY_SIZE (oplist->ops));
  struct pmap_update_op *op = &oplist->ops[oplist->nr_ops++];
  cpumap_or (&oplist->cpumap, &op->cpumap);
}

static unsigned int
pmap_update_oplist_count_mappings (const struct pmap_update_oplist *oplist,
                                   uint32_t cpu)
{
  uint32_t nr_mappings = 0;
  for (uint32_t i = 0; i < oplist->nr_ops; i++)
    {
      const _Auto op = &oplist->ops[i];
      if (!cpumap_test (&op->cpumap, cpu))
        continue;

      switch (op->operation)
        {
          case PMAP_UPDATE_OP_ENTER:
            ++nr_mappings;
            break;
          case PMAP_UPDATE_OP_REMOVE:
            nr_mappings += (op->remove_args.end - op->remove_args.start) /
                           PAGE_SIZE;
            break;
        case PMAP_UPDATE_OP_PROTECT:
            nr_mappings += (op->protect_args.end - op->protect_args.start) /
                           PAGE_SIZE;
            break;
          default:
            assert (! "invalid update operation");
        }
    }

  assert (nr_mappings);
  return (nr_mappings);
}

static void
pmap_update_request_array_init (struct pmap_update_request_array *array)
{
  for (size_t i = 0; i < ARRAY_SIZE (array->requests); i++)
    spinlock_init (&array->requests[i].lock);

  mutex_init (&array->lock);
}

static struct pmap_update_request_array*
pmap_update_request_array_acquire (void)
{
  thread_pin ();
  _Auto array = cpu_local_ptr (pmap_update_request_array);
  mutex_lock (&array->lock);
  return (array);
}

static void
pmap_update_request_array_release (struct pmap_update_request_array *array)
{
  mutex_unlock (&array->lock);
  thread_unpin ();
}

static void __init
pmap_syncer_init (struct pmap_syncer *syncer, uint32_t cpu)
{
  char name[SYSCNT_NAME_SIZE];
  struct pmap_update_queue *queue = &syncer->queue;

  spinlock_init (&queue->lock);
  list_init (&queue->requests);
  snprintf (name, sizeof (name), "pmap_updates/%u", cpu);
  syscnt_register (&syncer->sc_updates, name);
  snprintf (name, sizeof (name), "pmap_update_enters/%u", cpu);
  syscnt_register (&syncer->sc_update_enters, name);
  snprintf (name, sizeof (name), "pmap_update_removes/%u", cpu);
  syscnt_register (&syncer->sc_update_removes, name);
  snprintf (name, sizeof (name), "pmap_update_protects/%u", cpu);
  syscnt_register (&syncer->sc_update_protects, name);
}

static int __init
pmap_bootstrap (void)
{
  for (size_t i = 0; i < ARRAY_SIZE (pmap_get_kernel_pmap()->cpu_tables); ++i)
    {
      _Auto cpu_table = &pmap_kernel_cpu_tables[i];
      pmap_get_kernel_pmap()->cpu_tables[i] = cpu_table;
    }

  cpu_local_assign (pmap_current_ptr, pmap_get_kernel_pmap ());

  pmap_prot_table[VM_PROT_NONE] = 0;
  pmap_prot_table[VM_PROT_READ] = 0;
  pmap_prot_table[VM_PROT_WRITE] = PMAP_PTE_RW;
  pmap_prot_table[VM_PROT_WRITE | VM_PROT_READ] = PMAP_PTE_RW;
  pmap_prot_table[VM_PROT_EXECUTE] = 0;
  pmap_prot_table[VM_PROT_EXECUTE | VM_PROT_READ] = 0;
  pmap_prot_table[VM_PROT_EXECUTE | VM_PROT_WRITE] = PMAP_PTE_RW;
  pmap_prot_table[VM_PROT_ALL] = PMAP_PTE_RW;

  pmap_update_request_array_init (cpu_local_ptr (pmap_update_request_array));

  pmap_syncer_init (cpu_local_ptr (pmap_syncer), 0);

  pmap_update_oplist_ctor (&pmap_booter_oplist);
  tcb_set_pmap_update_oplist (tcb_current(), &pmap_booter_oplist);

  cpumap_zero (&pmap_booter_cpumap);
  cpumap_set (&pmap_booter_cpumap, 0);

  if (cpu_has_global_pages ())
    pmap_setup_global_pages ();

  return (0);
}

INIT_OP_DEFINE (pmap_bootstrap,
                INIT_OP_DEP (cpu_setup, true),
                INIT_OP_DEP (spinlock_setup, true),
                INIT_OP_DEP (syscnt_setup, true),
                INIT_OP_DEP (thread_bootstrap, true));

static void __init
pmap_setup_set_ptp_type (phys_addr_t ptp_pa, uint32_t index __unused,
                         uint32_t level)
{
  if (! level)
    return;

  struct vm_page *page = vm_page_lookup (ptp_pa);
  assert (page);

  if (vm_page_type (page) != VM_PAGE_PMAP)
    {
      assert (vm_page_type (page) == VM_PAGE_RESERVED);
      vm_page_set_type (page, 0, VM_PAGE_PMAP);
    }
}

static void __init
pmap_setup_fix_ptps (void)
{
  pmap_walk_vas (PMAP_START_ADDRESS, PMAP_END_KERNEL_ADDRESS,
                 pmap_setup_set_ptp_type);
}

static int __init
pmap_setup (void)
{
  pmap_setup_fix_ptps ();
  kmem_cache_init (&pmap_cache, "pmap", sizeof (struct pmap), 0, NULL, 0);
  kmem_cache_init (&pmap_update_oplist_cache, "pmap_update_oplist",
                   sizeof (struct pmap_update_oplist), CPU_L1_SIZE,
                   pmap_update_oplist_ctor, 0);
  return (0);
}

INIT_OP_DEFINE (pmap_setup,
                INIT_OP_DEP (kmem_setup, true),
                INIT_OP_DEP (log_setup, true),
                INIT_OP_DEP (pmap_bootstrap, true),
                INIT_OP_DEP (vm_page_setup, true));

void __init
pmap_ap_setup (void)
{
  cpu_local_assign (pmap_current_ptr, pmap_get_kernel_pmap ());

  if (cpu_has_global_pages ())
    cpu_enable_global_pages ();
  else
    cpu_tlb_flush();
}

static void __init
pmap_copy_cpu_table_page (const pmap_pte_t *sptp, unsigned int level,
                          struct vm_page *page)
{
  const _Auto pt_level = &pmap_pt_levels[level];
  pmap_pte_t *dptp = vm_page_direct_ptr (page);
  memcpy (dptp, sptp, pt_level->ptes_per_pt * sizeof (pmap_pte_t));
}

static void __init
pmap_copy_cpu_table_recursive (const pmap_pte_t *sptp, uint32_t level,
                               pmap_pte_t *dptp, uintptr_t start_va)
{
  assert (level);

  const _Auto pt_level = &pmap_pt_levels[level];
  memset (dptp, 0, pt_level->ptes_per_pt * sizeof (pmap_pte_t));

  for (uintptr_t i = 0, va = start_va;
       i < pt_level->ptes_per_pt;
       i++, va = P2END (va, 1UL << pt_level->skip))
    {
#ifdef __LP64__
      // Handle long mode canonical form.
      if (va == PMAP_END_ADDRESS)
        va = PMAP_START_KERNEL_ADDRESS;
#endif

      if (!pmap_pte_valid (sptp[i]))
        continue;
      else if (pmap_pte_large (sptp[i]))
        {
          dptp[i] = sptp[i];
          continue;
        }

      struct vm_page *page = vm_page_alloc (0, VM_PAGE_SEL_DIRECTMAP,
                                            VM_PAGE_PMAP);

      if (! page)
        panic ("pmap: unable to allocate page table page copy");

      phys_addr_t pa = vm_page_to_pa (page);
      dptp[i] = (sptp[i] & ~PMAP_PA_MASK) | (pa & PMAP_PA_MASK);

      if (level == 1 || pmap_pte_large (sptp[i]))
        pmap_copy_cpu_table_page (pmap_pte_next (sptp[i]), level - 1, page);
      else
        pmap_copy_cpu_table_recursive (pmap_pte_next (sptp[i]), level - 1,
                                       vm_page_direct_ptr (page), va);
    }
}

static void __init
pmap_copy_cpu_table (uint32_t cpu)
{
  assert (cpu);

  _Auto kernel_pmap = pmap_get_kernel_pmap ();
  assert (cpu < ARRAY_SIZE (kernel_pmap->cpu_tables));
  _Auto cpu_table = kernel_pmap->cpu_tables[cpu];
  uint32_t level = PMAP_NR_LEVELS - 1;
  const pmap_pte_t *sptp =
    pmap_ptp_from_pa (kernel_pmap->cpu_tables[cpu_id ()]->root_ptp_pa);

#ifdef CONFIG_X86_PAE
  cpu_table->root_ptp_pa = BOOT_VTOP ((uintptr_t)pmap_cpu_kpdpts[cpu]);
  pmap_pte_t *dptp = pmap_ptp_from_pa (cpu_table->root_ptp_pa);
#else
  struct vm_page *page = vm_page_alloc (0, VM_PAGE_SEL_DIRECTMAP,
                                        VM_PAGE_PMAP);
  if (! page)
    panic ("pmap: unable to allocate page table root page copy");

  cpu_table->root_ptp_pa = vm_page_to_pa (page);
  pmap_pte_t *dptp = vm_page_direct_ptr (page);
#endif

  pmap_copy_cpu_table_recursive (sptp, level, dptp, PMAP_START_ADDRESS);
}

void __init
pmap_mp_setup (void)
{
  struct cpumap *cpumap;
  if (cpumap_create (&cpumap) != 0)
    panic ("pmap: unable to create syncer cpumap");

  for (uint32_t cpu = 1; cpu < cpu_count (); cpu++)
    {
      pmap_update_request_array_init (percpu_ptr (pmap_update_request_array,
                                                  cpu));
      pmap_syncer_init (percpu_ptr (pmap_syncer, cpu), cpu);
    }

  for (uint32_t cpu = 0; cpu < cpu_count(); cpu++)
    {
      struct pmap_syncer *syncer = percpu_ptr (pmap_syncer, cpu);
      char name[THREAD_NAME_SIZE];
      struct thread_attr attr;

      snprintf (name, sizeof (name), THREAD_KERNEL_PREFIX "pmap_sync/%u", cpu);
      cpumap_zero (cpumap);
      cpumap_set (cpumap, cpu);
      thread_attr_init (&attr, name);
      thread_attr_set_cpumap (&attr, cpumap);
      thread_attr_set_priority (&attr, THREAD_SCHED_FS_PRIO_MAX);
      if (thread_create (&syncer->thread, &attr, pmap_sync, syncer) != 0)
        panic ("pmap: unable to create syncer thread");

      struct tcb *tcb = thread_get_tcb (syncer->thread);
      _Auto oplist = tcb_get_pmap_update_oplist (tcb);
      tcb_set_pmap_update_oplist (tcb, NULL);
      kmem_cache_free (&pmap_update_oplist_cache, oplist);
    }

  cpumap_destroy (cpumap);
  for (uint32_t cpu = 1; cpu < cpu_count (); cpu++)
    pmap_copy_cpu_table (cpu);

  pmap_do_remote_updates = 1;
}

int
pmap_thread_build (struct thread *thread)
{
  struct pmap_update_oplist *oplist;
  int error = pmap_update_oplist_create (&oplist);

  if (! error)
    tcb_set_pmap_update_oplist (thread_get_tcb (thread), oplist);

  return (error);
}

void
pmap_thread_cleanup (struct thread *thread)
{
  _Auto oplist = tcb_get_pmap_update_oplist (thread_get_tcb (thread));
  if (oplist)
    pmap_update_oplist_destroy (oplist);
}

int
pmap_kextract (uintptr_t va, phys_addr_t *pap)
{
  uint32_t level = PMAP_NR_LEVELS - 1;
  _Auto kernel_pmap = pmap_get_kernel_pmap ();
  pmap_pte_t *pte, *ptp =
    pmap_ptp_from_pa (kernel_pmap->cpu_tables[cpu_id ()]->root_ptp_pa);

  while (1)
    {
      const _Auto pt_level = &pmap_pt_levels[level];
      pte = &ptp[pmap_pte_index (va, pt_level)];

      if (!pmap_pte_valid (*pte))
        return (EFAULT);

      if (!level || pmap_pte_large (*pte))
        break;

      --level;
      ptp = pmap_pte_next (*pte);
    }

  *pap = *pte & PMAP_PA_MASK;
  return (0);
}

int
pmap_create (struct pmap **pmapp)
{
  struct pmap *pmap = kmem_cache_alloc (&pmap_cache);
  if (! pmap)
    return (ENOMEM);

  for (size_t i = 0; i < ARRAY_SIZE (pmap->cpu_tables); ++i)
    pmap->cpu_tables[i] = NULL;

  *pmapp = pmap;
  return (0);
}

int
pmap_copy (const struct pmap *src, struct pmap **dst)
{
  int error = pmap_create (dst);
  if (! error)
    **dst = *src;
  return (error);
}

void
pmap_destroy (struct pmap *pmap)
{
  kmem_cache_free (&pmap_cache, pmap);
}

static int
pmap_enter_local (struct pmap *pmap, uintptr_t va, phys_addr_t pa,
                  int prot, int flags __unused)
{
  // TODO Page attributes.
  pmap_pte_t pte_bits = PMAP_PTE_RW;

  if (pmap != pmap_get_kernel_pmap ())
    pte_bits |= PMAP_PTE_US;

  uint32_t level = PMAP_NR_LEVELS - 1;
  pmap_pte_t *pte, *ptp =
    pmap_ptp_from_pa (pmap->cpu_tables[cpu_id ()]->root_ptp_pa);

  const struct pmap_pt_level *pt_level;
  while (1)
    {
      pt_level = &pmap_pt_levels[level];
      pte = &ptp[pmap_pte_index (va, pt_level)];

      if (! level)
        break;

      if (pmap_pte_valid (*pte))
        ptp = pmap_pte_next (*pte);
      else
        {
          struct vm_page *page = vm_page_alloc (0, VM_PAGE_SEL_DIRECTMAP,
                                                VM_PAGE_PMAP);
          if (! page)
            {
              log_warning ("pmap: page table page allocation failure");
              return (ENOMEM);
            }

          phys_addr_t ptp_pa = vm_page_to_pa (page);
          ptp = pmap_ptp_from_pa (ptp_pa);
          pmap_ptp_clear (ptp);
          pmap_pte_set (pte, ptp_pa, pte_bits, pt_level);
        }

      --level;
    }

  assert (!pmap_pte_valid (*pte));
  pte_bits = ((pmap == pmap_get_kernel_pmap ()) ? PMAP_PTE_G : PMAP_PTE_US) |
             pmap_prot_table[prot & VM_PROT_ALL];
  pmap_pte_set (pte, pa, pte_bits, pt_level);
  return (0);
}

int
pmap_enter (struct pmap *pmap, uintptr_t va, phys_addr_t pa,
            int prot, int flags)
{
  va = vm_page_trunc (va);
  pa = vm_page_trunc (pa);
  assert (pmap_range_valid (pmap, va, va + PAGE_SIZE));

  _Auto oplist = pmap_update_oplist_get ();
  int error = pmap_update_oplist_prepare (oplist, pmap);

  if (error)
    return error;

  _Auto op = pmap_update_oplist_prepare_op (oplist);

  if (flags & PMAP_PEF_GLOBAL)
    cpumap_copy (&op->cpumap, cpumap_all ());
  else
    {
      cpumap_zero (&op->cpumap);
      cpumap_set (&op->cpumap, cpu_id ());
    }

  op->operation = PMAP_UPDATE_OP_ENTER;
  op->enter_args.va = va;
  op->enter_args.pa = pa;
  op->enter_args.prot = prot;
  op->enter_args.flags = flags & ~PMAP_PEF_GLOBAL;
  pmap_update_oplist_finish_op (oplist);
  return (0);
}

static void
pmap_remove_local_single (struct pmap *pmap, uintptr_t va)
{
  uint32_t level = PMAP_NR_LEVELS - 1;
  pmap_pte_t *pte, *ptp =
    pmap_ptp_from_pa (pmap->cpu_tables[cpu_id ()]->root_ptp_pa);

  while (1)
    {
      const _Auto pt_level = &pmap_pt_levels[level];
      pte = &ptp[pmap_pte_index (va, pt_level)];

      if (!pmap_pte_valid (*pte))
        return;
      else if (! level)
        break;

      --level;
      ptp = pmap_pte_next (*pte);
    }

  pmap_pte_clear (pte);
}

static void
pmap_remove_local (struct pmap *pmap, uintptr_t start, uintptr_t end)
{
  for (; start < end; start += PAGE_SIZE)
    pmap_remove_local_single (pmap, start);
}

int
pmap_remove (struct pmap *pmap, uintptr_t va, const struct cpumap *cpumap)
{
  va = vm_page_trunc (va);
  assert (pmap_range_valid (pmap, va, va + PAGE_SIZE));

  _Auto oplist = pmap_update_oplist_get ();
  int error = pmap_update_oplist_prepare (oplist, pmap);
  if (error)
    return (error);

  // Attempt naive merge with previous operation.
  _Auto op = pmap_update_oplist_prev_op (oplist);

  if (op &&
      op->operation == PMAP_UPDATE_OP_REMOVE &&
      op->remove_args.end == va &&
      cpumap_cmp (&op->cpumap, cpumap) == 0)
    {
      op->remove_args.end = va + PAGE_SIZE;
      return (0);
    }

  op = pmap_update_oplist_prepare_op (oplist);
  cpumap_copy (&op->cpumap, cpumap);
  op->operation = PMAP_UPDATE_OP_REMOVE;
  op->remove_args.start = va;
  op->remove_args.end = va + PAGE_SIZE;
  pmap_update_oplist_finish_op (oplist);
  return (0);
}

static void
pmap_protect_local (struct pmap *pmap __unused, uintptr_t start __unused,
                    uintptr_t end __unused, int prot __unused)
{
  // TODO Implement.
  panic ("pmap: pmap_protect not implemented");
}

int
pmap_protect (struct pmap *pmap, uintptr_t va, int prot,
              const struct cpumap *cpumap)
{
  va = vm_page_trunc (va);
  assert (pmap_range_valid (pmap, va, va + PAGE_SIZE));

  _Auto oplist = pmap_update_oplist_get ();
  int error = pmap_update_oplist_prepare (oplist, pmap);
  if (error)
    return (error);

  // Attempt naive merge with previous operation.
  _Auto op = pmap_update_oplist_prev_op (oplist);

  if (op &&
       op->operation == PMAP_UPDATE_OP_PROTECT &&
       op->protect_args.end == va &&
       op->protect_args.prot == prot &&
       cpumap_cmp (&op->cpumap, cpumap) == 0)
    {
      op->protect_args.end = va + PAGE_SIZE;
      return (0);
    }

  op = pmap_update_oplist_prepare_op (oplist);
  cpumap_copy (&op->cpumap, cpumap);
  op->operation = PMAP_UPDATE_OP_PROTECT;
  op->protect_args.start = va;
  op->protect_args.end = va + PAGE_SIZE;
  op->protect_args.prot = prot;
  pmap_update_oplist_finish_op (oplist);
  return (0);
}

static void
pmap_flush_tlb (struct pmap *pmap, uintptr_t start, uintptr_t end)
{
  if (pmap != pmap_current () && pmap != pmap_get_kernel_pmap ())
    return;

  for (; start < end; start += PAGE_SIZE)
    cpu_tlb_flush_va (start);
}

static void
pmap_flush_tlb_all (struct pmap *pmap)
{
  if (pmap == pmap_get_kernel_pmap ())
    cpu_tlb_flush_all ();
  else if (pmap == pmap_current ())
    cpu_tlb_flush ();
}

static int
pmap_update_enter (struct pmap *pmap, int flush,
                   const struct pmap_update_enter_args *args)
{
  int error = pmap_enter_local (pmap, args->va, args->pa,
                                args->prot, args->flags);

  if (!error && flush)
    pmap_flush_tlb (pmap, args->va, args->va + PAGE_SIZE);

  return (error);
}

static void
pmap_update_remove (struct pmap *pmap, int flush,
                    const struct pmap_update_remove_args *args)
{
  pmap_remove_local (pmap, args->start, args->end);
  if (flush)
    pmap_flush_tlb (pmap, args->start, args->end);
}

static void
pmap_update_protect (struct pmap *pmap, int flush,
                     const struct pmap_update_protect_args *args)
{
  pmap_protect_local (pmap, args->start, args->end, args->prot);
  if (flush)
    pmap_flush_tlb (pmap, args->start, args->end);
}

static int
pmap_update_local (const struct pmap_update_oplist *oplist,
                   uint32_t nr_mappings)
{
  struct pmap_syncer *syncer = cpu_local_ptr (pmap_syncer);
  syscnt_inc (&syncer->sc_updates);
  int error = 0,
      global_tlb_flush = nr_mappings > PMAP_UPDATE_MAX_MAPPINGS;

  for (uint32_t i = 0; i < oplist->nr_ops; i++)
    {
      const _Auto op = &oplist->ops[i];
      if (!cpumap_test (&op->cpumap, cpu_id ()))
        continue;

      switch (op->operation)
        {
          case PMAP_UPDATE_OP_ENTER:
            syscnt_inc (&syncer->sc_update_enters);
            error = pmap_update_enter (oplist->pmap, !global_tlb_flush,
                                       &op->enter_args);
            break;
          case PMAP_UPDATE_OP_REMOVE:
            syscnt_inc (&syncer->sc_update_removes);
            pmap_update_remove (oplist->pmap, !global_tlb_flush,
                                &op->remove_args);
            break;
          case PMAP_UPDATE_OP_PROTECT:
            syscnt_inc (&syncer->sc_update_protects);
            pmap_update_protect (oplist->pmap, !global_tlb_flush,
                                 &op->protect_args);
            break;
          default:
            assert (! "invalid update operation");
        }

      if (error)
        return (error);
    }

  if (global_tlb_flush)
    pmap_flush_tlb_all (oplist->pmap);

  return (0);
}

int
pmap_update (struct pmap *pmap)
{
  _Auto oplist = pmap_update_oplist_get ();

  if (pmap != oplist->pmap)
    { // Make sure pmap_update() is called before manipulating another pmap.
      assert (!oplist->pmap);
      return (0);
    }

  assert (oplist->nr_ops);
  int error;

  if (!pmap_do_remote_updates)
    {
      uint32_t nr_mappings = pmap_update_oplist_count_mappings (oplist,
                                                                cpu_id ());
      error = pmap_update_local (oplist, nr_mappings);
      goto out;
    }

  error = 0;
  _Auto array = pmap_update_request_array_acquire ();

  cpumap_for_each (&oplist->cpumap, cpu)
    {
      struct pmap_syncer *syncer = percpu_ptr (pmap_syncer, cpu);
      struct pmap_update_queue *queue = &syncer->queue;
      struct pmap_update_request *request = &array->requests[cpu];

      request->sender = thread_self ();
      request->oplist = oplist;
      request->nr_mappings = pmap_update_oplist_count_mappings (oplist, cpu);
      request->done = 0;
      request->error = 0;

      SPINLOCK_GUARD (&queue->lock, false);
      list_insert_tail (&queue->requests, &request->node);
      thread_wakeup (syncer->thread);
  }

  // TODO Improve scalability.
  cpumap_for_each (&oplist->cpumap, cpu)
    {
      struct pmap_update_request *request = &array->requests[cpu];
      SPINLOCK_GUARD (&request->lock, false);

      while (!request->done)
        thread_sleep (&request->lock, request, "pmaprq");

      if (!error && request->error)
        error = request->error;
    }

  pmap_update_request_array_release (array);

out:
  cpumap_zero (&oplist->cpumap);
  oplist->pmap = NULL;
  oplist->nr_ops = 0;
  return (error);
}

static void
pmap_sync (void *arg)
{
  struct pmap_syncer *self = arg;
  struct pmap_update_queue *queue = &self->queue;

  while (1)
    {
      spinlock_lock (&queue->lock);

      while (list_empty (&queue->requests))
        thread_sleep (&queue->lock, queue, "pmapq");

      _Auto request = list_first_entry (&queue->requests,
                                        struct pmap_update_request, node);
      list_remove (&request->node);
      spinlock_unlock (&queue->lock);

      int error = pmap_update_local (request->oplist, request->nr_mappings);

      spinlock_lock (&request->lock);
      request->done = 1;
      request->error = error;
      thread_wakeup (request->sender);
      spinlock_unlock (&request->lock);
    }
}

void
pmap_load (struct pmap *pmap)
{
  assert (!cpu_intr_enabled ());
  assert (!thread_preempt_enabled ());

  if (pmap_current () == pmap)
    return;

  // TODO Lazy TLB invalidation.
  cpu_local_assign (pmap_current_ptr, pmap);

  // TODO Implement per-CPU page tables for non-kernel pmaps.
  _Auto cpu_table = pmap->cpu_tables[cpu_id ()];
  cpu_set_cr3 (cpu_table->root_ptp_pa);
}
