/*
 * Copyright (c) 2014-2018 Remy Noel.
 * Copyright (c) 2014-2018 Richard Braun.
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
#include <stdint.h>

#include <kern/clock.h>
#include <kern/init.h>
#include <kern/log.h>
#include <kern/perfmon.h>
#include <kern/percpu.h>
#include <machine/cpu.h>
#include <machine/pmu_intel.h>

// Intel raw event IDs.
#define PMU_INTEL_RE_CYCLE          0
#define PMU_INTEL_RE_REF_CYCLE      1
#define PMU_INTEL_RE_INSTRUCTION    2
#define PMU_INTEL_RE_CACHE_REF      3
#define PMU_INTEL_RE_CACHE_MISS     4
#define PMU_INTEL_RE_BRANCH         5
#define PMU_INTEL_RE_BRANCH_MISS    6

// PMU MSR addresses
#define PMU_INTEL_MSR_PMC0      0x0c1
#define PMU_INTEL_MSR_EVTSEL0   0x186

// V2 MSR addresses
#define PMU_INTEL_MSR_GLOBAL_STATUS     0x038e
#define PMU_INTEL_MSR_GLOBAL_CTRL       0x038f
#define PMU_INTEL_MSR_GLOBAL_OVF_CTRL   0x0390

// Event Select Register addresses
#define PMU_INTEL_EVTSEL_USR    0x00010000
#define PMU_INTEL_EVTSEL_OS     0x00020000
#define PMU_INTEL_EVTSEL_INT    0x00100000
#define PMU_INTEL_EVTSEL_EN     0x00400000

#define PMU_INTEL_ID_VERSION_MASK       0x000000ff
#define PMU_INTEL_ID_NR_PMCS_MASK       0x0000ff00
#define PMU_INTEL_ID_NR_PMCS_OFFSET     8
#define PMU_INTEL_ID_PMC_WIDTH_MASK     0x00ff0000
#define PMU_INTEL_ID_PMC_WIDTH_OFFSET   16
#define PMU_INTEL_ID_EVLEN_MASK         0xff000000
#define PMU_INTEL_ID_EVLEN_OFFSET       24
#define PMU_INTEL_ID_EVLEN_MAX          7

#define PMU_INTEL_MAX_NR_PMCS   8

/*
 * Global PMU properties.
 *
 * The bitmap is used to implement counter allocation, where each bit denotes
 * whether a counter is available or not.
 */
struct pmu_intel
{
  uint32_t version;
  uint32_t nr_pmcs;
  uint32_t pmc_bm;
  uint32_t pmc_indexes[PMU_INTEL_MAX_NR_PMCS];
  uint32_t pmc_width;
  uint32_t events;
};

static struct pmu_intel pmu_intel;

// Intel hardware events.
#define PMU_INTEL_EVENT_CYCLE          0x01
#define PMU_INTEL_EVENT_INSTRUCTION    0x02
#define PMU_INTEL_EVENT_REF_CYCLE      0x04
#define PMU_INTEL_EVENT_CACHE_REF      0x08
#define PMU_INTEL_EVENT_CACHE_MISS     0x10
#define PMU_INTEL_EVENT_BRANCH         0x20
#define PMU_INTEL_EVENT_BRANCH_MISS    0x40

struct pmu_intel_event_code
{
  uint32_t hw_event_id;
  uint16_t event_select;
  uint16_t umask;
};

static const uint32_t pmu_intel_raw_events[] =
{
  [PERFMON_EV_CYCLE]          = PMU_INTEL_RE_CYCLE,
  [PERFMON_EV_REF_CYCLE]      = PMU_INTEL_RE_REF_CYCLE,
  [PERFMON_EV_INSTRUCTION]    = PMU_INTEL_RE_INSTRUCTION,
  [PERFMON_EV_CACHE_REF]      = PMU_INTEL_RE_CACHE_REF,
  [PERFMON_EV_CACHE_MISS]     = PMU_INTEL_RE_CACHE_MISS,
  [PERFMON_EV_BRANCH]         = PMU_INTEL_RE_BRANCH,
  [PERFMON_EV_BRANCH_MISS]    = PMU_INTEL_RE_BRANCH_MISS,
};

static const struct pmu_intel_event_code pmu_intel_event_codes[] =
{
  [PMU_INTEL_RE_CYCLE]        = { PMU_INTEL_EVENT_CYCLE,        0x3c, 0x00 },
  [PMU_INTEL_RE_REF_CYCLE]    = { PMU_INTEL_EVENT_REF_CYCLE,    0x3c, 0x01 },
  [PMU_INTEL_RE_INSTRUCTION]  = { PMU_INTEL_EVENT_INSTRUCTION,  0xc0, 0x00 },
  [PMU_INTEL_RE_CACHE_REF]    = { PMU_INTEL_EVENT_CACHE_REF,    0x2e, 0x4f },
  [PMU_INTEL_RE_CACHE_MISS]   = { PMU_INTEL_EVENT_CACHE_MISS,   0x2e, 0x41 },
  [PMU_INTEL_RE_BRANCH]       = { PMU_INTEL_EVENT_BRANCH,       0xc4, 0x00 },
  [PMU_INTEL_RE_BRANCH_MISS]  = { PMU_INTEL_EVENT_BRANCH_MISS,  0xc5, 0x00 },
};

static struct pmu_intel*
pmu_intel_get (void)
{
  return (&pmu_intel);
}

static uint64_t
pmu_intel_get_status (void)
{
  return (cpu_get_msr64 (PMU_INTEL_MSR_GLOBAL_STATUS));
}

static void
pmu_intel_ack_status (uint64_t status)
{
  return (cpu_set_msr64 (PMU_INTEL_MSR_GLOBAL_OVF_CTRL, status));
}

static int
pmu_intel_translate (uint32_t *raw_event_idp, uint32_t event_id)
{
  if (event_id >= ARRAY_SIZE (pmu_intel_raw_events))
    return (EINVAL);

  *raw_event_idp = pmu_intel_raw_events[event_id];
  return (0);
}

static int
pmu_intel_alloc (uint32_t *pmc_idp, uint32_t pmc_index, uint32_t raw_event_id)
{
  assert (raw_event_id < ARRAY_SIZE (pmu_intel_event_codes));

  struct pmu_intel *pmu = pmu_intel_get ();
  uint32_t hw_event_id = pmu_intel_event_codes[raw_event_id].hw_event_id;

  if (!(pmu->events & hw_event_id))
    return (EINVAL);
  else if (!pmu->pmc_bm)
    return (EAGAIN);

  uint32_t pmc_id = __builtin_ffs (pmu->pmc_bm) - 1;
  assert (pmc_id < ARRAY_SIZE (pmu->pmc_indexes));
  pmu->pmc_indexes[pmc_id] = pmc_index;
  pmu->pmc_bm &= ~(1U << pmc_id);
  *pmc_idp = pmc_id;
  return (0);
}

static void
pmu_intel_free (uint32_t pmc_id)
{
  struct pmu_intel *pmu = pmu_intel_get ();
  uint32_t mask = 1U << pmc_id;
  assert (!(pmu->pmc_bm & mask));
  pmu->pmc_bm |= mask;
}

static void
pmu_intel_start (uint32_t pmc_id, uint32_t raw_event_id)
{
  assert (raw_event_id < ARRAY_SIZE (pmu_intel_event_codes));

  const _Auto code = &pmu_intel_event_codes[raw_event_id];
  struct pmu_intel *pmu = pmu_intel_get();

  // TODO Handle PERFMON_EF_KERN/PERFMON_EF_USER.
  uint32_t evtsel = PMU_INTEL_EVTSEL_EN | PMU_INTEL_EVTSEL_OS |
                    PMU_INTEL_EVTSEL_USR | (code->umask << 8) |
                    code->event_select;

  if (pmu->version >= 2)
    evtsel |= PMU_INTEL_EVTSEL_INT;

  cpu_set_msr (PMU_INTEL_MSR_EVTSEL0 + pmc_id, 0, evtsel);
}

static void
pmu_intel_stop (uint32_t pmc_id)
{
  cpu_set_msr (PMU_INTEL_MSR_EVTSEL0 + pmc_id, 0, 0);
}

static uint64_t
pmu_intel_read (uint32_t pmc_id)
{
  return (cpu_get_msr64 (PMU_INTEL_MSR_PMC0 + pmc_id));
}

static int
pmu_intel_consume_bits (uint64_t *bits)
{
  int bit = __builtin_ffsll (*bits) - 1;

  if (bit < 0)
    return (bit);

  *bits &= ~(1U << bit);
  return (bit);
}

static void
pmu_intel_handle_overflow_intr (void)
{
  uint64_t status = pmu_intel_get_status ();
  if (! status)
    return;

  pmu_intel_ack_status (status);
  struct pmu_intel *pmu = pmu_intel_get ();

  status &= ((1ULL << pmu->pmc_width) - 1);

  while (1)
    {
      int pmc_id = pmu_intel_consume_bits (&status);

      if (pmc_id < 0)
        break;

      uint32_t pmc_index = pmu->pmc_indexes[pmc_id];
      perfmon_report_overflow (pmc_index);
    }
}

static struct perfmon_dev_ops pmu_intel_ops __read_mostly =
{
  .translate  = pmu_intel_translate,
  .alloc      = pmu_intel_alloc,
  .free       = pmu_intel_free,
  .start      = pmu_intel_start,
  .stop       = pmu_intel_stop,
  .read       = pmu_intel_read,
};

static struct perfmon_dev pmu_intel_dev __read_mostly;

static void
pmu_intel_percpu_init (void)
{
  const struct pmu_intel *pmu = pmu_intel_get();
  uint64_t pmc_mask = (1ULL << pmu->nr_pmcs) - 1;
  cpu_set_msr64 (PMU_INTEL_MSR_GLOBAL_CTRL, 0x700000000 | pmc_mask);
}

static struct percpu_op pmu_intel_percpu_op =
    PERCPU_OP_INITIALIZER (pmu_intel_percpu_init);

static int __init
pmu_intel_setup (void)
{
  uint32_t eax = 0xa, ebx, ecx, edx, ev_len;
  const struct cpu *cpu = cpu_current();

  if (cpu_vendor_id (cpu) != CPU_VENDOR_INTEL)
    return (0);
  else if (cpu_cpuid_max_basic (cpu) < eax)
    return (ENODEV);

  struct pmu_intel *pmu = pmu_intel_get ();
  cpu_cpuid (&eax, &ebx, &ecx, &edx);
  pmu->version = eax & PMU_INTEL_ID_VERSION_MASK;

  if (!pmu->version)
    return (ENODEV);

  pmu->nr_pmcs = (eax & PMU_INTEL_ID_NR_PMCS_MASK) >>
                 PMU_INTEL_ID_NR_PMCS_OFFSET;

  if (pmu->nr_pmcs > ARRAY_SIZE (pmu->pmc_indexes))
    {
      log_err ("pmu: invalid number of PMCs (%u)", pmu->nr_pmcs);
      return (ENODEV);
    }

  pmu->pmc_bm = (1U << pmu->nr_pmcs) - 1;
  pmu->pmc_width = (eax & PMU_INTEL_ID_PMC_WIDTH_MASK)
                   >> PMU_INTEL_ID_PMC_WIDTH_OFFSET;
  ev_len = (eax & PMU_INTEL_ID_EVLEN_MASK) >> PMU_INTEL_ID_EVLEN_OFFSET;

  assert (ev_len <= PMU_INTEL_ID_EVLEN_MAX);

  pmu->events = ~ebx & ((1U << ev_len) - 1);

  pmu_intel_dev.ops = &pmu_intel_ops;
  pmu_intel_dev.pmc_width = pmu->pmc_width;

  if (pmu->version >= 2)
    {
      percpu_register_op (&pmu_intel_percpu_op);
      pmu_intel_ops.handle_overflow_intr = pmu_intel_handle_overflow_intr;
    }

  perfmon_register (&pmu_intel_dev);
  log_info ("pmu: intel v%d, nr_pmcs:%u pmc_width:%u events:%#x nr_events:%u",
            pmu->version, pmu->nr_pmcs, pmu->pmc_width, pmu->events,
            __builtin_popcount (pmu->events));
  return (0);
}

INIT_OP_DEFINE (pmu_intel_setup,
                INIT_OP_DEP (cpu_setup, true),
                INIT_OP_DEP (log_setup, true),
                INIT_OP_DEP (percpu_setup, true),
                INIT_OP_DEP (perfmon_bootstrap, true));
