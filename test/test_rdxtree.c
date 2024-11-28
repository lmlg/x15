/*
 * Copyright (c) 2022 Agustina Arzille.
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
 * This test module tests the radix tree API.
 */

#include <kern/rcu.h>
#include <kern/rdxtree.h>

#include <test/test.h>

static int
rdxtree_count (struct rdxtree *tree)
{
  struct rdxtree_iter iter;
  void *ptr;
  int count = 0;

  rdxtree_for_each (tree, &iter, ptr)
    ++count;

  return (count);
}

#define RDXTREE_SIZE   1024

TEST_DEFERRED (rdxtree)
{
  struct rdxtree tree;
  int error;
  void *ptr;
  int *val = alloca (sizeof (int));

  rdxtree_init (&tree, RDXTREE_KEY_ALLOC);

  for (int i = 0; i < RDXTREE_SIZE; ++i)
    {
      error = rdxtree_insert (&tree, (rdxtree_key_t)i, val + i);
      test_assert_zero (error);
    }

  test_assert_eq (rdxtree_count (&tree), RDXTREE_SIZE);
  for (int i = RDXTREE_SIZE - 1; i >= 0; --i)
    {
      ptr = rdxtree_lookup (&tree, (rdxtree_key_t)i);
      test_assert_eq (ptr, val + i);
    }

  test_assert_eq (val + 33, rdxtree_remove (&tree, 33));
  val += RDXTREE_SIZE;

  rdxtree_key_t key;
  error = rdxtree_insert_alloc (&tree, val, &key);
  test_assert_eq (key, 33);
  test_assert_zero (error);
  ++val;

  void **slot;
  error = rdxtree_insert_alloc_slot (&tree, val, &key, &slot);
  test_assert_zero (error);
  test_assert_ge (key, RDXTREE_SIZE);
  test_assert_eq (rdxtree_load_slot (slot), val);

  ptr = rdxtree_replace_slot (slot, val + 1);
  test_assert_eq (ptr, val);
  test_assert_eq (rdxtree_load_slot (slot), val + 1);

  test_assert_zero (rdxtree_lookup (&tree, key + 2));
  test_assert_zero (rdxtree_lookup_slot (&tree, key + 2));
  test_assert_zero (rdxtree_remove (&tree, key + 2));

  void *node;
  int idx;
  slot = rdxtree_lookup_common (&tree, 64, true, &node, &idx);
  test_assert_nonnull (slot);
  rdxtree_remove_node_idx (&tree, node, idx);
  test_assert_zero (rdxtree_lookup (&tree, 64));

  rcu_wait ();
  rdxtree_remove_all (&tree);
  test_assert_zero (rdxtree_count (&tree));

  return (TEST_OK);
}
