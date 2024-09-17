/*
 * Copyright (c) 2024 Agustina Arzille.
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
 * This test module tests the physical mapping API for VM maps.
 */

#include <stdio.h>

#include <kern/capability.h>
#include <kern/kmessage.h>
#include <kern/task.h>

#include <test/test.h>

#include <vm/map.h>

#define TEST_VM_MAP_PHYS_OFFSET   (PAGE_SIZE * 14)

/*
 * Use a global to accumlate the returned pages since we need this
 * address to reside in userspace, and the stack for the landing
 * pad is in kernel space.
 */
static void* test_vm_map_phys_room;

#if !defined (__LP64__) && defined (__i386__)
__attribute__ ((regparm (2)))
#endif
static void
test_vm_map_phys_entry (struct ipc_msg *msg, struct ipc_msg_data *data)
{
  if (!(data->flags & IPC_MSG_KERNEL))
    cap_reply_bytes (0, 0, -EINVAL);

  _Auto kmsg = (struct kmessage *)msg->iovs->iov_base;

  if (kmsg->type == KMSG_TYPE_MMAP_REQ)
    {
      assert (kmsg->mmap_req.prot & VM_PROT_READ);
      assert (kmsg->mmap_req.offset == TEST_VM_MAP_PHYS_OFFSET);

      ssize_t rv = cap_reply_pagereq (0, 0);
      assert (rv == -EINVAL);

      cap_reply_bytes (0, 0, 0);
    }
  else if (kmsg->type != KMSG_TYPE_PAGE_REQ)
    cap_reply_bytes (0, 0, -EINVAL);

  int flags = VM_MAP_FLAGS (VM_PROT_RDWR, VM_PROT_RDWR,
                            VM_INHERIT_SHARE, VM_ADV_DEFAULT,
                            VM_MAP_PHYS | VM_MAP_ANON);
  uintptr_t addr = 0, psz = kmsg->page_req.end - kmsg->page_req.start;
  int error = vm_map_enter (vm_map_self (), &addr, psz, flags, 0, 0);
  assert (! error);

  uintptr_t npg = psz / PAGE_SIZE, last_va = addr + psz,
            *buf = test_vm_map_phys_room;

  for (uintptr_t i = 0; i < npg; ++i, last_va -= PAGE_SIZE)
    {
      *(unsigned char *)addr = (unsigned char)((i + 1) * 20);
      buf[i] = last_va - PAGE_SIZE;
      addr += PAGE_SIZE;
    }

  ssize_t rv = cap_reply_bytes (0, 0, 0);
  assert (rv == -EINVAL);

  cap_reply_pagereq (buf, npg);
  panic ("shouldn't return");
}

static void
test_vm_map_phys_handle_dirty (struct vm_object *obj, uintptr_t va)
{
  void *ptr;
  int ret = vm_map_anon_alloc (&ptr, vm_map_self (), PAGE_SIZE * 4);
  assert (ret == 0);

  struct
    {
      uint64_t offsets[16];
      struct iovec iovs[3];
      struct cap_page_info pginfo;
    } *p = ptr;

  p->pginfo.size = sizeof (p->pginfo);
  p->pginfo.flags = 0;
  p->pginfo.offset_cnt = ARRAY_SIZE (p->offsets);
  p->pginfo.offsets = p->offsets;
  p->pginfo.iovs = NULL;
  p->pginfo.iov_cnt = 0;

  ret = vm_object_map_dirty (obj, &p->pginfo);
  assert (ret == 3);

  assert (*(unsigned char *)p->pginfo.vme.addr == 0xff);
  // This call will clean the page, before marking it read-only.
  vm_map_remove (vm_map_self (), p->pginfo.vme.addr,
                 p->pginfo.vme.addr + PAGE_SIZE);
  // This mutation will mark it writable and dirty.
  *(unsigned char *)va = 0xfe;

  ret = vm_object_list_dirty (obj, &p->pginfo);
  assert (ret == 3);

  p->iovs[0].iov_base = (char *)ptr + PAGE_SIZE;
  p->iovs[1].iov_base = (char *)ptr + PAGE_SIZE * 2;
  p->iovs[2].iov_base = (char *)ptr + PAGE_SIZE * 3;
  p->iovs[0].iov_len = p->iovs[1].iov_len = p->iovs[2].iov_len = PAGE_SIZE;

  p->pginfo.iovs = p->iovs;
  p->pginfo.iov_cnt = ARRAY_SIZE (p->iovs);
  p->offsets[3] = PAGE_SIZE;
  p->pginfo.offset_cnt = 4;

  ret = vm_object_copy_pages (obj, &p->pginfo);
  assert (ret == PAGE_SIZE * 3);
  assert (p->offsets[3] & 1);
  assert (*(unsigned char *)p->iovs[0].iov_base == 0xfe);
  assert (*(unsigned char *)p->iovs[1].iov_base == 0xff);
  assert (*(unsigned char *)p->iovs[2].iov_base == 0xff);

  // Make sure the pages are clean.
  for (uint32_t i = 0; i < p->pginfo.offset_cnt - 1; ++i)
    {
      _Auto page = vm_object_lookup (obj, p->offsets[i]);
      assert (page != NULL);
      assert (page->dirty == VM_PAGE_CLEAN);
      vm_page_unref (page);
    }
}

static void
test_vm_map_phys_cap (void *arg __unused)
{
  struct cap_flow *flow;
  int error = cap_flow_create (&flow, CAP_FLOW_EXT_PAGER | CAP_FLOW_PAGER_FLUSHES,
                               1, (uintptr_t)test_vm_map_phys_entry);
  assert (! error);

  struct cap_channel *ch;
  error = cap_channel_create (&ch, flow, 2);
  assert (! error);

  void *ptr;
  error = vm_map_anon_alloc (&ptr, vm_map_self (), PAGE_SIZE * 3);
  assert (! error);

  _Auto stkpage = vm_page_alloc (0, VM_PAGE_SEL_DIRECTMAP,
                                 VM_PAGE_KERNEL, 0);
  assert (stkpage);
  vm_page_init_refcount (stkpage);

  {
    struct
      {
        struct ipc_msg msg;
        struct iovec iov;
        struct ipc_msg_data mdata;
        struct cap_thread_info info;
        uint64_t buf[16];
      } *p = ptr;

    p->iov.iov_base = p->buf;
    p->iov.iov_len = sizeof (p->buf);

    p->msg.iovs = &p->iov;
    p->msg.iov_cnt = 1;

    error = cap_flow_add_lpad (flow, (char *)vm_page_direct_ptr (stkpage) +
                               PAGE_SIZE, PAGE_SIZE, &p->msg,
                               &p->mdata, &p->info);
    assert (! error);
    test_vm_map_phys_room = (char *)ptr + PAGE_SIZE * 2;
  }

  uintptr_t va = 0;
  int flags = VM_MAP_FLAGS (VM_PROT_RDWR, VM_PROT_RDWR, VM_INHERIT_SHARE,
                            VM_ADV_DEFAULT, 0);
  _Auto obj = cap_channel_get_vmobj (ch);
  assert (obj);
  assert (obj->flags & VM_OBJECT_EXTERNAL);

  error = vm_map_enter (vm_map_self (), &va, PAGE_SIZE * 3, flags,
                        obj, TEST_VM_MAP_PHYS_OFFSET);
  assert (! error);

  for (int i = 0; i < 3; ++i)
    {
      assert (*(unsigned char *)(va + PAGE_SIZE * i) == 60 - (20 * i));
      *(unsigned char *)(va + PAGE_SIZE * i) = 0xff;
    }

  test_vm_map_phys_handle_dirty (obj, va);

  _Auto entry = vm_map_find (vm_map_self (), va + PAGE_SIZE);
  assert (entry);
  assert (va + PAGE_SIZE >= entry->start);
  assert (entry->object == obj);
  vm_map_entry_put (entry);
  cap_channel_put_vmobj (ch);

  vm_page_unref (stkpage);

  cap_base_rel (ch);
  cap_base_rel (flow);
}

static void
test_vm_map_phys (void *arg __unused)
{
  _Auto map = vm_map_self ();
  uintptr_t addr = 0;
  int flags = VM_MAP_FLAGS (VM_PROT_RDWR, VM_PROT_RDWR, VM_INHERIT_SHARE,
                            VM_ADV_DEFAULT, VM_MAP_PHYS | VM_MAP_ANON);
  int error = vm_map_enter (map, &addr, PAGE_SIZE * 3, flags, 0, 0);

  assert (! error);

  // Pin the thread to prevent the 'pmap_extract' call from failing below.
  thread_pin ();

  {
    unsigned char *ptr = (unsigned char *)(addr + PAGE_SIZE);
    unsigned char val = 0;

    for (size_t i = 0; i < PAGE_SIZE; ++i)
      val |= ptr[i];

    assert (val == 0);
    *ptr = 42;
  }

  phys_addr_t pa;
  error = pmap_extract (map->pmap, addr + PAGE_SIZE, &pa);
  thread_unpin ();
  assert (! error);

  uintptr_t va2 = 0;
  error = vm_map_enter (map, &va2, PAGE_SIZE, flags & ~VM_MAP_ANON, 0, pa);
  assert (! error);

  assert (*(unsigned char *)va2 == 42);
}

TEST_DEFERRED (vm_map_phys)
{
  int error;
  struct thread *thread;

  error = test_util_create_thr (&thread, test_vm_map_phys,
                                NULL, "vm_map_phys");

  assert (! error);
  thread_join (thread);

  error = test_util_create_thr (&thread, test_vm_map_phys_cap,
                                NULL, "vm_map_phys_cap");
  assert (! error);
  thread_join (thread);

  return (TEST_OK);
}
