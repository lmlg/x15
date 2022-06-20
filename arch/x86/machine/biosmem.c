/*
 * Copyright (c) 2010-2016 Richard Braun.
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
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <kern/init.h>
#include <kern/log.h>
#include <kern/macros.h>
#include <kern/panic.h>

#include <machine/biosmem.h>
#include <machine/boot.h>
#include <machine/cpu.h>
#include <machine/multiboot.h>
#include <machine/page.h>
#include <machine/pmap.h>
#include <machine/pmem.h>
#include <machine/types.h>

#include <vm/page.h>

#define BIOSMEM_MAX_BOOT_DATA   64

/*
 * Boot data descriptor.
 *
 * The start and end addresses must not be page-aligned, since there
 * could be more than one range inside a single page.
 */
struct biosmem_boot_data
{
  phys_addr_t start;
  phys_addr_t end;
  bool temporary;
};

// Sorted array of boot data descriptors.
static struct biosmem_boot_data biosmem_boot_data_array[BIOSMEM_MAX_BOOT_DATA]
  __bootdata;
static unsigned int biosmem_nr_boot_data __bootdata;

/*
 * Maximum number of entries in the BIOS memory map.
 *
 * Because of adjustments of overlapping ranges, the memory map can grow
 * to twice this size.
 */
#define BIOSMEM_MAX_MAP_SIZE 128

// Memory range types.
#define BIOSMEM_TYPE_AVAILABLE   1
#define BIOSMEM_TYPE_RESERVED    2
#define BIOSMEM_TYPE_ACPI        3
#define BIOSMEM_TYPE_NVS         4
#define BIOSMEM_TYPE_UNUSABLE    5
#define BIOSMEM_TYPE_DISABLED    6

// Memory map entry.
struct biosmem_map_entry
{
  uint64_t base_addr;
  uint64_t length;
  unsigned int type;
};

/*
 * Memory map built from the information passed by the boot loader.
 *
 * If the boot loader didn't pass a valid memory map, a simple map is built
 * based on the mem_lower and mem_upper multiboot fields.
 */
static struct biosmem_map_entry biosmem_map[BIOSMEM_MAX_MAP_SIZE * 2]
  __bootdata;
static unsigned int biosmem_map_size __bootdata;

// Temporary copy of the BIOS Data Area.
static char biosmem_bda[BIOSMEM_BDA_SIZE] __bootdata;

// Contiguous block of physical memory.
struct biosmem_zone
{
  phys_addr_t start;
  phys_addr_t end;
};

// Physical zone boundaries.
static struct biosmem_zone biosmem_zones[PMEM_MAX_ZONES] __bootdata;

/*
 * Boundaries of the simple bootstrap heap.
 *
 * This heap is located above BIOS memory.
 */
static phys_addr_t biosmem_heap_start __bootdata;
static phys_addr_t biosmem_heap_bottom __bootdata;
static phys_addr_t biosmem_heap_top __bootdata;
static phys_addr_t biosmem_heap_end __bootdata;

/*
 * Boot allocation policy.
 *
 * Top-down allocations are normally preferred to avoid unnecessarily
 * filling the DMA zone.
 */
static bool biosmem_heap_topdown __bootdata;

static char biosmem_panic_inval_boot_data[] __bootdata
  = "biosmem: invalid boot data";
static char biosmem_panic_too_many_boot_data[] __bootdata
  = "biosmem: too many boot data ranges";
static char biosmem_panic_too_big_msg[] __bootdata
  = "biosmem: too many memory map entries";
static char biosmem_panic_setup_msg[] __bootdata
  = "biosmem: unable to set up the early memory allocator";
static char biosmem_panic_nozone_msg[] __bootdata
  = "biosmem: unable to find any memory zone";
static char biosmem_panic_inval_msg[] __bootdata
  = "biosmem: attempt to allocate 0 page";
static char biosmem_panic_nomem_msg[] __bootdata
  = "biosmem: unable to allocate memory";

void __boot
biosmem_register_boot_data (phys_addr_t start, phys_addr_t end, bool temporary)
{
  if (start >= end)
    boot_panic (biosmem_panic_inval_boot_data);
  else if (biosmem_nr_boot_data == ARRAY_SIZE (biosmem_boot_data_array))
    boot_panic (biosmem_panic_too_many_boot_data);

  uint32_t i;
  for (i = 0; i < biosmem_nr_boot_data; i++)
    {
      // Check if the new range overlaps.
      if (end > biosmem_boot_data_array[i].start &&
          start < biosmem_boot_data_array[i].end)
        {

          /*
           * If it does, check whether it's part of another range.
           * For example, this applies to debugging symbols directly
           * taken from the kernel image.
           */
          if (start >= biosmem_boot_data_array[i].start &&
              end <= biosmem_boot_data_array[i].end)
            {

              /*
               * If it's completely included, make sure that a permanent
               * range remains permanent.
               *
               * XXX This means that if one big range is first registered
               * as temporary, and a smaller range inside of it is
               * registered as permanent, the bigger range becomes
               * permanent. It's not easy nor useful in practice to do
               * better than that.
               */
              if (biosmem_boot_data_array[i].temporary != temporary)
                biosmem_boot_data_array[i].temporary = false;

              return;
            }

          boot_panic (biosmem_panic_inval_boot_data);
        }

      if (end <= biosmem_boot_data_array[i].start)
        break;
    }

  boot_memmove (&biosmem_boot_data_array[i + 1],
                &biosmem_boot_data_array[i],
                (biosmem_nr_boot_data - i) *
                  sizeof (*biosmem_boot_data_array));

  biosmem_boot_data_array[i].start = start;
  biosmem_boot_data_array[i].end = end;
  biosmem_boot_data_array[i].temporary = temporary;
  ++biosmem_nr_boot_data;
}

static void __init
biosmem_unregister_boot_data (phys_addr_t start, phys_addr_t end)
{
  if (start >= end)
    panic ("%s", biosmem_panic_inval_boot_data);

  assert (biosmem_nr_boot_data != 0);

  uint32_t i;
  for (i = 0; biosmem_nr_boot_data; i++)
    if (start == biosmem_boot_data_array[i].start &&
        end == biosmem_boot_data_array[i].end)
      break;

  if (i == biosmem_nr_boot_data)
    return;

  log_debug ("biosmem: unregister boot data: %llx:%llx",
             (unsigned long long)biosmem_boot_data_array[i].start,
             (unsigned long long)biosmem_boot_data_array[i].end);

  --biosmem_nr_boot_data;
  memmove (&biosmem_boot_data_array[i],
           &biosmem_boot_data_array[i + 1],
           (biosmem_nr_boot_data - i) * sizeof (*biosmem_boot_data_array));
}

static void __boot
biosmem_map_build (const struct multiboot_raw_info *mbi)
{
  uintptr_t addr = mbi->mmap_addr;
  _Auto mb_entry = (struct multiboot_raw_mmap_entry *) addr;
  _Auto mb_end = (struct multiboot_raw_mmap_entry *) (addr + mbi->mmap_length);
  struct biosmem_map_entry *start = biosmem_map,
                           *entry = start,
                           *end = entry + BIOSMEM_MAX_MAP_SIZE;

  for (; mb_entry < mb_end && entry < end; ++entry)
    {
      entry->base_addr = mb_entry->base_addr;
      entry->length = mb_entry->length;
      entry->type = mb_entry->type;

      mb_entry = (void *)((char *)mb_entry + sizeof (mb_entry->size) +
                          mb_entry->size);
    }

  biosmem_map_size = entry - start;
}

static void __boot
biosmem_map_build_simple (const struct multiboot_raw_info *mbi)
{
  struct biosmem_map_entry *entry = biosmem_map;
  entry->base_addr = 0;
  entry->length = mbi->mem_lower << 10;
  entry->type = BIOSMEM_TYPE_AVAILABLE;

  entry++;
  entry->base_addr = BIOSMEM_END;
  entry->length = mbi->mem_upper << 10;
  entry->type = BIOSMEM_TYPE_AVAILABLE;

  biosmem_map_size = 2;
}

static int __boot
biosmem_map_entry_is_invalid (const struct biosmem_map_entry *entry)
{
  return (entry->base_addr + entry->length <= entry->base_addr);
}

static void __boot
biosmem_map_filter (void)
{
  for (uint32_t i = 0; i < biosmem_map_size; ++i)
    {
      _Auto entry = &biosmem_map[i];

      if (biosmem_map_entry_is_invalid (entry))
        {
          --biosmem_map_size;
          boot_memmove (entry, entry + 1,
                        (biosmem_map_size - i) * sizeof (*entry));
          continue;
        }
    }
}

static void __boot
biosmem_map_sort (void)
{
  // Simple insertion sort.
  for (uint32_t i = 1; i < biosmem_map_size; i++)
    {
      struct biosmem_map_entry tmp;
      boot_memcpy (&tmp, &biosmem_map[i], sizeof (tmp));

      uint32_t j;
      for (j = i - 1; j < i; j--)
        {
          if (biosmem_map[j].base_addr < tmp.base_addr)
            break;

          boot_memcpy (&biosmem_map[j + 1], &biosmem_map[j],
                       sizeof (biosmem_map[j + 1]));
        }

      boot_memcpy (&biosmem_map[j + 1], &tmp, sizeof (biosmem_map[j + 1]));
    }
}

static void __boot
biosmem_map_adjust (void)
{
  biosmem_map_filter ();

  /*
   * Resolve overlapping areas, giving priority to most restrictive
   * (i.e. numerically higher) types.
   */
  for (uint32_t i = 0; i < biosmem_map_size; i++)
    {
      struct biosmem_map_entry tmp;
      _Auto a = &biosmem_map[i];
      uint64_t a_end = a->base_addr + a->length;

      for (uint32_t j = i + 1; j < biosmem_map_size;)
        {
          _Auto b = &biosmem_map[j];
          uint64_t b_end = b->base_addr + b->length;

          if (a->base_addr >= b_end || a_end <= b->base_addr)
            {
              j++;
              continue;
            }

          struct biosmem_map_entry *first, *second;
          if (a->base_addr < b->base_addr)
            {
              first = a;
              second = b;
            }
          else
            {
              first = b;
              second = a;
            }

          uint64_t last_end;
          uint32_t last_type;

          if (a_end > b_end)
            {
              last_end = a_end;
              last_type = a->type;
            }
          else
            {
              last_end = b_end;
              last_type = b->type;
            }

          tmp.base_addr = second->base_addr;
          tmp.length = MIN (a_end, b_end) - tmp.base_addr;
          tmp.type = MAX (a->type, b->type);
          first->length = tmp.base_addr - first->base_addr;
          second->base_addr += tmp.length;
          second->length = last_end - second->base_addr;
          second->type = last_type;

          // Filter out invalid entries.
          if (biosmem_map_entry_is_invalid (a) &&
              biosmem_map_entry_is_invalid (b))
            {
              boot_memcpy (a, &tmp, sizeof (*a));
              --biosmem_map_size;
              boot_memmove (b, b + 1, (biosmem_map_size - j) * sizeof (*b));
              continue;
            }
          else if (biosmem_map_entry_is_invalid (a))
            {
              boot_memcpy (a, &tmp, sizeof (*a));
              j++;
              continue;
            }
          else if (biosmem_map_entry_is_invalid (b))
            {
              boot_memcpy (b, &tmp, sizeof (*b));
              j++;
              continue;
            }

          if (tmp.type == a->type)
            first = a;
          else if (tmp.type == b->type)
            first = b;
          else
            {

              /*
               * If the overlapping area can't be merged with one of its
               * neighbors, it must be added as a new entry.
               */

              if (biosmem_map_size >= ARRAY_SIZE (biosmem_map))
                boot_panic (biosmem_panic_too_big_msg);

              boot_memcpy (&biosmem_map[biosmem_map_size], &tmp,
                           sizeof (biosmem_map[biosmem_map_size]));
              ++biosmem_map_size;
              ++j;
              continue;
            }

          if (first->base_addr > tmp.base_addr)
            first->base_addr = tmp.base_addr;

          first->length += tmp.length;
          j++;
        }
    }

  biosmem_map_sort ();
}

/*
 * Find addresses of physical memory within a given range.
 *
 * This function considers the memory map with the [*phys_start, *phys_end]
 * range on entry, and returns the lowest address of physical memory
 * in *phys_start, and the highest address of unusable memory immediately
 * following physical memory in *phys_end.
 *
 * These addresses are normally used to establish the range of a zone.
 */
static int __boot
biosmem_map_find_avail (phys_addr_t *phys_start, phys_addr_t *phys_end)
{
  phys_addr_t zone_start = (phys_addr_t)-1,
              zone_end = (phys_addr_t)-1;
  const _Auto map_end = biosmem_map + biosmem_map_size;

  for (_Auto entry = biosmem_map; entry < map_end; ++entry)
    {
      if (entry->type != BIOSMEM_TYPE_AVAILABLE)
        continue;

      uint64_t start = vm_page_round (entry->base_addr);
      if (start >= *phys_end)
        break;

      uint64_t end = vm_page_trunc (entry->base_addr + entry->length);
      if (start < end && start < *phys_end && end > *phys_start)
        {
          if (zone_start == (phys_addr_t)-1)
            zone_start = start;

          zone_end = end;
        }
    }

  if (zone_start == (phys_addr_t)-1 || zone_end == (phys_addr_t)-1)
    return (-1);

  if (zone_start > *phys_start)
    *phys_start = zone_start;

  if (zone_end < *phys_end)
    *phys_end = zone_end;

  return (0);
}

static void __boot
biosmem_set_zone (uint32_t zone_index, phys_addr_t start, phys_addr_t end)
{
  biosmem_zones[zone_index].start = start;
  biosmem_zones[zone_index].end = end;
}

static phys_addr_t __boot
biosmem_zone_end (uint32_t zone_index)
{
  return (biosmem_zones[zone_index].end);
}

static phys_addr_t __boot
biosmem_zone_size (uint32_t zone_index)
{
  return (biosmem_zones[zone_index].end - biosmem_zones[zone_index].start);
}

static int __boot
biosmem_find_avail_clip (phys_addr_t *avail_start, phys_addr_t *avail_end,
                         phys_addr_t data_start, phys_addr_t data_end)
{
  assert (data_start < data_end);

  phys_addr_t orig_end = data_end;
  data_start = vm_page_trunc (data_start);
  data_end = vm_page_round (data_end);

  if (data_end < orig_end)
    boot_panic (biosmem_panic_inval_boot_data);
  else if (data_end <= *avail_start || data_start >= *avail_end)
    return (0);

  if (data_start > *avail_start)
    *avail_end = data_start;
  else
    {
      if (data_end >= *avail_end)
        return (-1);

      *avail_start = data_end;
    }

  return (0);
}

/*
 * Find available memory in the given range.
 *
 * The search starts at the given start address, up to the given end address.
 * If a range is found, it is stored through the avail_startp and avail_endp
 * pointers.
 *
 * The range boundaries are page-aligned on return.
 */
static int __boot
biosmem_find_avail (phys_addr_t start, phys_addr_t end,
                    phys_addr_t *avail_start, phys_addr_t *avail_end)
{
  assert (start <= end);

  phys_addr_t orig_start = start;
  start = vm_page_round (start);
  end = vm_page_trunc (end);

  if (start < orig_start || start >= end)
    return (-1);

  *avail_start = start;
  *avail_end = end;

  for (uint32_t i = 0; i < biosmem_nr_boot_data; i++)
    if (biosmem_find_avail_clip (avail_start, avail_end,
                                 biosmem_boot_data_array[i].start,
                                 biosmem_boot_data_array[i].end) != 0)
      return (-1);

  return (0);
}

static void __boot
biosmem_setup_allocator (const struct multiboot_raw_info *mbi)
{
  /*
   * Find some memory for the heap. Look for the largest unused area in
   * upper memory, carefully avoiding all boot data.
   */
  phys_addr_t end = vm_page_trunc ((mbi->mem_upper + 1024) << 10);

#ifndef __LP64__
  if (end > PMEM_DIRECTMAP_LIMIT)
    end = PMEM_DIRECTMAP_LIMIT;
#endif

  phys_addr_t max_heap_start = 0, max_heap_end = 0, start = BIOSMEM_END;

  while (1)
    {
      phys_addr_t heap_start, heap_end;

      if (biosmem_find_avail (start, end, &heap_start, &heap_end))
        break;
      else if (heap_end - heap_start > max_heap_end - max_heap_start)
        {
          max_heap_start = heap_start;
          max_heap_end = heap_end;
        }

      start = heap_end;
    }

  if (max_heap_start >= max_heap_end)
    boot_panic (biosmem_panic_setup_msg);

  biosmem_heap_start = max_heap_start;
  biosmem_heap_end = max_heap_end;
  biosmem_heap_bottom = biosmem_heap_start;
  biosmem_heap_top = biosmem_heap_end;
  biosmem_heap_topdown = true;

  // Prevent biosmem_free_usable() from releasing the heap.
  biosmem_register_boot_data (biosmem_heap_start, biosmem_heap_end, false);
}

void __boot
biosmem_bootstrap (const struct multiboot_raw_info *mbi)
{
  boot_memcpy (biosmem_bda, (const void *)BIOSMEM_BDA_ADDR, BIOSMEM_BDA_SIZE);

  if (mbi->flags & MULTIBOOT_LOADER_MMAP)
    biosmem_map_build (mbi);
  else
    biosmem_map_build_simple (mbi);

  biosmem_map_adjust ();

  phys_addr_t phys_start = BIOSMEM_BASE, phys_end = PMEM_DMA_LIMIT;
  if (biosmem_map_find_avail (&phys_start, &phys_end) != 0)
    boot_panic (biosmem_panic_nozone_msg);

  biosmem_set_zone (PMEM_ZONE_DMA, phys_start, phys_end);

  phys_start = PMEM_DMA_LIMIT;
#ifdef PMEM_DMA32_LIMIT
  phys_end = PMEM_DMA32_LIMIT;
  if (biosmem_map_find_avail (&phys_start, &phys_end) != 0)
    goto out;

  biosmem_set_zone (PMEM_ZONE_DMA32, phys_start, phys_end);
  phys_start = PMEM_DMA32_LIMIT;
#endif
  phys_end = PMEM_DIRECTMAP_LIMIT;
  if (biosmem_map_find_avail (&phys_start, &phys_end) != 0)
    goto out;

  biosmem_set_zone (PMEM_ZONE_DIRECTMAP, phys_start, phys_end);

  phys_start = PMEM_DIRECTMAP_LIMIT;
  phys_end = PMEM_HIGHMEM_LIMIT;
  if (biosmem_map_find_avail (&phys_start, &phys_end) == 0)
    biosmem_set_zone (PMEM_ZONE_HIGHMEM, phys_start, phys_end);

out:
  biosmem_setup_allocator (mbi);
}

void* __boot
biosmem_bootalloc (uint32_t nr_pages)
{
  size_t size = vm_page_ptob (nr_pages);
  if (! size)
    boot_panic (biosmem_panic_inval_msg);

  uintptr_t addr;
  if (biosmem_heap_topdown)
    {
      addr = biosmem_heap_top - size;

      if (addr < biosmem_heap_start || addr > biosmem_heap_top)
        boot_panic (biosmem_panic_nomem_msg);

      biosmem_heap_top = addr;
    }
  else
    {
      addr = biosmem_heap_bottom;
      uintptr_t end = addr + size;

      if (end > biosmem_heap_end || end < biosmem_heap_bottom)
        boot_panic (biosmem_panic_nomem_msg);

      biosmem_heap_bottom = end;
    }

  return (boot_memset ((void *)addr, 0, size));
}

const void*
biosmem_get_bda (void)
{
  return (biosmem_bda);
}

phys_addr_t __boot
biosmem_directmap_end (void)
{
  if (biosmem_zone_size (PMEM_ZONE_DIRECTMAP) != 0)
    return (biosmem_zone_end (PMEM_ZONE_DIRECTMAP));
  else if (biosmem_zone_size (PMEM_ZONE_DMA32) != 0)
    return (biosmem_zone_end (PMEM_ZONE_DMA32));
  else
    return (biosmem_zone_end (PMEM_ZONE_DMA));
}

static const char* __init
biosmem_type_desc (unsigned int type)
{
  switch (type)
    {
      case BIOSMEM_TYPE_AVAILABLE:
        return ("available");
      case BIOSMEM_TYPE_RESERVED:
        return ("reserved");
      case BIOSMEM_TYPE_ACPI:
        return ("ACPI");
      case BIOSMEM_TYPE_NVS:
        return ("ACPI NVS");
      case BIOSMEM_TYPE_UNUSABLE:
        return ("unusable");
      default:
        return ("unknown (reserved)");
    }
}

static void __init
biosmem_map_show (void)
{
  log_debug ("biosmem: physical memory map:");
  _Auto entry = biosmem_map;
  _Auto end = entry + biosmem_map_size;

  for (; entry < end; ++entry)
    log_debug ("biosmem: %018llx:%018llx, %s",
               (unsigned long long)entry->base_addr,
               (unsigned long long)(entry->base_addr + entry->length),
               biosmem_type_desc (entry->type));

  log_debug ("biosmem: heap: %llx:%llx",
             (unsigned long long) biosmem_heap_start,
             (unsigned long long) biosmem_heap_end);
}

static void __init
biosmem_load_zone (struct biosmem_zone *zone, uint64_t max_phys_end)
{
  phys_addr_t phys_start = zone->start,
              phys_end = zone->end;
  uint32_t zone_index = zone - biosmem_zones;

  if (phys_end > max_phys_end)
    {
      if (max_phys_end <= phys_start)
        {
          log_warning ("biosmem: zone %s physically unreachable, "
                       "not loaded", vm_page_zone_name (zone_index));
          return;
        }

      log_warning ("biosmem: warning: zone %s truncated to %#llx",
                   vm_page_zone_name (zone_index),
                   (unsigned long long) max_phys_end);
      phys_end = max_phys_end;
    }

  vm_page_load (zone_index, phys_start, phys_end);

  /*
   * Clip the remaining available heap to fit it into the loaded
   * zone if possible.
   */

  if (biosmem_heap_top > phys_start && biosmem_heap_bottom < phys_end)
    {
      phys_addr_t avail_start = MAX (biosmem_heap_bottom, phys_start),
                  avail_end = MIN (biosmem_heap_top, phys_end);

      vm_page_load_heap (zone_index, avail_start, avail_end);
    }
}

static int __init
biosmem_setup (void)
{
  biosmem_map_show ();

  uint32_t phys_addr_width = cpu_phys_addr_width (cpu_current ());
  uint64_t max_phys_end = !phys_addr_width || phys_addr_width == 64 ?
                          (uint64_t)-1 : ((uint64_t)1 << phys_addr_width);

  for (size_t i = 0; i < ARRAY_SIZE (biosmem_zones); i++)
    {
      if (biosmem_zone_size (i) == 0)
        break;

      biosmem_load_zone (&biosmem_zones[i], max_phys_end);
    }

  return (0);
}

INIT_OP_DEFINE (biosmem_setup,
                INIT_OP_DEP (cpu_setup, true),
                INIT_OP_DEP (log_setup, true));

static void __init
biosmem_unregister_temporary_boot_data (void)
{
  for (uint32_t i = 0; i < biosmem_nr_boot_data; i++)
    {
      _Auto data = &biosmem_boot_data_array[i];
      if (!data->temporary)
        continue;

      biosmem_unregister_boot_data (data->start, data->end);
      i = (unsigned int)-1;
    }
}

static void __init
biosmem_free_usable_range (phys_addr_t start, phys_addr_t end)
{
  log_debug ("biosmem: release to vm_page: %llx:%llx (%lluk)",
             (unsigned long long) start, (unsigned long long) end,
             (unsigned long long) ((end - start) >> 10));

  while (start < end)
    {
      _Auto page = vm_page_lookup (start);
      assert (page);
      vm_page_manage (page);
      start += PAGE_SIZE;
    }
}

static void __init
biosmem_free_usable_entry (phys_addr_t start, phys_addr_t end)
{
  while (1)
    {
      phys_addr_t avail_start, avail_end;
      if (biosmem_find_avail (start, end, &avail_start, &avail_end) != 0)
        break;

      biosmem_free_usable_range (avail_start, avail_end);
      start = avail_end;
    }
}

static int __init
biosmem_free_usable (void)
{
  biosmem_unregister_temporary_boot_data ();

  for (uint32_t i = 0; i < biosmem_map_size; i++)
    {
      _Auto entry = &biosmem_map[i];
      if (entry->type != BIOSMEM_TYPE_AVAILABLE)
        continue;

      uint64_t start = vm_page_round (entry->base_addr);
      if (start >= PMEM_HIGHMEM_LIMIT)
        break;

      uint64_t end = vm_page_trunc (entry->base_addr + entry->length);

      if (end > PMEM_HIGHMEM_LIMIT)
        end = PMEM_HIGHMEM_LIMIT;

      if (start < BIOSMEM_BASE)
        start = BIOSMEM_BASE;

      if (start < end)
        biosmem_free_usable_entry (start, end);
    }

  return (0);
}

INIT_OP_DEFINE (biosmem_free_usable,
                INIT_OP_DEP (boot_save_data, true),
                INIT_OP_DEP (log_setup, true),
                INIT_OP_DEP (vm_page_setup, true));
