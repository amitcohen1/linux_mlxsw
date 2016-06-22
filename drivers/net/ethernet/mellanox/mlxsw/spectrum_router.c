/*
 * drivers/net/ethernet/mellanox/mlxsw/spectrum_router.c
 * Copyright (c) 2016 Mellanox Technologies. All rights reserved.
 * Copyright (c) 2016 Jiri Pirko <jiri@mellanox.com>
 * Copyright (c) 2016 Ido Schimmel <idosch@mellanox.com>
 * Copyright (c) 2016 Yotam Gigi <yotamg@mellanox.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the names of the copyright holders nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/rhashtable.h>
#include <linux/bitops.h>
#include <linux/in6.h>
#include <linux/hashtable.h>
#include <linux/notifier.h>
#include <net/neighbour.h>
#include <net/netevent.h>
#include <net/arp.h>

#include "spectrum.h"
#include "core.h"
#include "port.h"
#include "reg.h"

#define MLXSW_SP_ROUTER_NEIGH_MIN_UPDATE_TIME 2000

#define mlxsw_sp_prefix_usage_for_each(prefix, prefix_usage) \
	for_each_set_bit(prefix, (prefix_usage)->b, MLXSW_SP_PREFIX_COUNT)

static bool
mlxsw_sp_prefix_usage_subset(struct mlxsw_sp_prefix_usage *prefix_usage1,
			     struct mlxsw_sp_prefix_usage *prefix_usage2)
{
	unsigned char prefix;

	mlxsw_sp_prefix_usage_for_each(prefix, prefix_usage1) {
		if (!test_bit(prefix, prefix_usage2->b))
			return false;
	}
	return true;
}

static bool
mlxsw_sp_prefix_usage_eq(struct mlxsw_sp_prefix_usage *prefix_usage1,
			 struct mlxsw_sp_prefix_usage *prefix_usage2)
{
	return !memcmp(prefix_usage1, prefix_usage2, sizeof(*prefix_usage1));
}

static bool
mlxsw_sp_prefix_usage_none(struct mlxsw_sp_prefix_usage *prefix_usage)
{
	struct mlxsw_sp_prefix_usage prefix_usage_none = {{ 0 } };

	return mlxsw_sp_prefix_usage_eq(prefix_usage, &prefix_usage_none);
}

static void
mlxsw_sp_prefix_usage_cpy(struct mlxsw_sp_prefix_usage *prefix_usage1,
			  struct mlxsw_sp_prefix_usage *prefix_usage2)
{
	memcpy(prefix_usage1, prefix_usage2, sizeof(*prefix_usage1));
}

static void
mlxsw_sp_prefix_usage_zero(struct mlxsw_sp_prefix_usage *prefix_usage)
{
	memset(prefix_usage, 0, sizeof(*prefix_usage));
}

static void
mlxsw_sp_prefix_usage_set(struct mlxsw_sp_prefix_usage *prefix_usage,
			  unsigned char prefix_len)
{
	set_bit(prefix_len, prefix_usage->b);
}

static void
mlxsw_sp_prefix_usage_clear(struct mlxsw_sp_prefix_usage *prefix_usage,
			    unsigned char prefix_len)
{
	clear_bit(prefix_len, prefix_usage->b);
}

struct mlxsw_sp_fib_key {
	unsigned char addr[sizeof(struct in6_addr)];
	unsigned char prefix_len;
};

enum mlxsw_sp_fib_entry_type {
	MLXSW_SP_FIB_ENTRY_TYPE_REMOTE,
	MLXSW_SP_FIB_ENTRY_TYPE_LOCAL,
	MLXSW_SP_FIB_ENTRY_TYPE_TRAP,
};

struct mlxsw_sp_nexthop_group;

struct mlxsw_sp_fib_entry {
	struct rhash_head ht_node;
	struct mlxsw_sp_fib_key key;
	enum mlxsw_sp_fib_entry_type type;
	u8 added:1;
	u16 rif_id; /* used for action local */
	struct mlxsw_sp_vr *vr;
	struct list_head nexthop_group_node;
	struct mlxsw_sp_nexthop_group *nh_group;
};

struct mlxsw_sp_fib {
	struct rhashtable ht;
	unsigned long prefix_refcnt[MLXSW_SP_PREFIX_COUNT];
	struct mlxsw_sp_prefix_usage prefix_usage;
};

static const struct rhashtable_params mlxsw_sp_fib_ht_params = {
	.key_offset = offsetof(struct mlxsw_sp_fib_entry, key),
	.head_offset = offsetof(struct mlxsw_sp_fib_entry, ht_node),
	.key_len = sizeof(struct mlxsw_sp_fib_key),
	.automatic_shrinking = true,
};

static int mlxsw_sp_fib_entry_insert(struct mlxsw_sp_fib *fib,
				     struct mlxsw_sp_fib_entry *fib_entry)
{
	unsigned char prefix_len = fib_entry->key.prefix_len;
	int err;

	err = rhashtable_insert_fast(&fib->ht, &fib_entry->ht_node,
				     mlxsw_sp_fib_ht_params);
	if (err)
		return err;
	if (fib->prefix_refcnt[prefix_len]++ == 0)
		mlxsw_sp_prefix_usage_set(&fib->prefix_usage, prefix_len);
	return 0;
}

static void mlxsw_sp_fib_entry_remove(struct mlxsw_sp_fib *fib,
				      struct mlxsw_sp_fib_entry *fib_entry)
{
	unsigned char prefix_len = fib_entry->key.prefix_len;

	if (--fib->prefix_refcnt[prefix_len] == 0)
		mlxsw_sp_prefix_usage_clear(&fib->prefix_usage, prefix_len);
	rhashtable_remove_fast(&fib->ht, &fib_entry->ht_node,
			       mlxsw_sp_fib_ht_params);
}

static struct mlxsw_sp_fib_entry *
mlxsw_sp_fib_entry_create(struct mlxsw_sp_fib *fib, const void *addr,
			  size_t addr_len, unsigned char prefix_len)
{
	struct mlxsw_sp_fib_entry *fib_entry;

	fib_entry = kzalloc(sizeof(*fib_entry), GFP_KERNEL);
	if (!fib_entry)
		return NULL;
	memcpy(fib_entry->key.addr, addr, addr_len);
	fib_entry->key.prefix_len = prefix_len;
	return fib_entry;
}

static void mlxsw_sp_fib_entry_destroy(struct mlxsw_sp_fib_entry *fib_entry)
{
	kfree(fib_entry);
}

static struct mlxsw_sp_fib_entry *
mlxsw_sp_fib_entry_lookup(struct mlxsw_sp_fib *fib, const void *addr,
			  size_t addr_len, unsigned char prefix_len)
{
	struct mlxsw_sp_fib_key key = {{ 0 } };

	memcpy(key.addr, addr, addr_len);
	key.prefix_len = prefix_len;
	return rhashtable_lookup_fast(&fib->ht, &key, mlxsw_sp_fib_ht_params);
}

static struct mlxsw_sp_fib *mlxsw_sp_fib_create(void)
{
	struct mlxsw_sp_fib *fib;
	int err;

	fib = kzalloc(sizeof(*fib), GFP_KERNEL);
	if (!fib)
		return ERR_PTR(-ENOMEM);
	err = rhashtable_init(&fib->ht, &mlxsw_sp_fib_ht_params);
	if (err)
		goto err_rhashtable_init;
	return fib;

err_rhashtable_init:
	kfree(fib);
	return ERR_PTR(err);
}

static void mlxsw_sp_fib_destroy(struct mlxsw_sp_fib *fib)
{
	rhashtable_destroy(&fib->ht);
	kfree(fib);
}

static struct mlxsw_sp_lpm_tree *
mlxsw_sp_lpm_tree_find_unused(struct mlxsw_sp *mlxsw_sp)
{
	static struct mlxsw_sp_lpm_tree *lpm_tree;
	int i;

	for (i = 0; i < MLXSW_SP_LPM_TREE_COUNT; i++) {
		lpm_tree = &mlxsw_sp->router.lpm_trees[i];
		if (lpm_tree->ref_count == 0)
			return lpm_tree;
	}
	return NULL;
}

static int mlxsw_sp_lpm_tree_alloc(struct mlxsw_sp *mlxsw_sp,
				   struct mlxsw_sp_lpm_tree *lpm_tree)
{
	char ralta_pl[MLXSW_REG_RALTA_LEN];

	mlxsw_reg_ralta_pack(ralta_pl, true, lpm_tree->proto, lpm_tree->id);
	return mlxsw_reg_write(mlxsw_sp->core, MLXSW_REG(ralta), ralta_pl);
}

static int mlxsw_sp_lpm_tree_free(struct mlxsw_sp *mlxsw_sp,
				  struct mlxsw_sp_lpm_tree *lpm_tree)
{
	char ralta_pl[MLXSW_REG_RALTA_LEN];

	mlxsw_reg_ralta_pack(ralta_pl, false, lpm_tree->proto, lpm_tree->id);
	return mlxsw_reg_write(mlxsw_sp->core, MLXSW_REG(ralta), ralta_pl);
}

static int
mlxsw_sp_lpm_tree_left_struct_set(struct mlxsw_sp *mlxsw_sp,
				  struct mlxsw_sp_prefix_usage *prefix_usage,
				  struct mlxsw_sp_lpm_tree *lpm_tree)
{
	char ralst_pl[MLXSW_REG_RALST_LEN];
	u8 root_bin = 0;
	u8 prefix;
	u8 last_prefix = MLXSW_REG_RALST_BIN_NO_CHILD;

	mlxsw_sp_prefix_usage_for_each(prefix, prefix_usage)
		root_bin = prefix;

	mlxsw_reg_ralst_pack(ralst_pl, root_bin, lpm_tree->id);
	mlxsw_sp_prefix_usage_for_each(prefix, prefix_usage) {
		if (prefix == 0)
			continue;
		mlxsw_reg_ralst_bin_pack(ralst_pl, prefix, last_prefix,
					 MLXSW_REG_RALST_BIN_NO_CHILD);
		last_prefix = prefix;
	}
	return mlxsw_reg_write(mlxsw_sp->core, MLXSW_REG(ralst), ralst_pl);
}

static struct mlxsw_sp_lpm_tree *
mlxsw_sp_lpm_tree_create(struct mlxsw_sp *mlxsw_sp,
			 struct mlxsw_sp_prefix_usage *prefix_usage,
			 enum mlxsw_sp_l3proto proto)
{
	struct mlxsw_sp_lpm_tree *lpm_tree;
	int err;

	lpm_tree = mlxsw_sp_lpm_tree_find_unused(mlxsw_sp);
	if (!lpm_tree)
		return ERR_PTR(-EBUSY);
	lpm_tree->proto = proto;
	err = mlxsw_sp_lpm_tree_alloc(mlxsw_sp, lpm_tree);
	if (err)
		return ERR_PTR(err);

	err = mlxsw_sp_lpm_tree_left_struct_set(mlxsw_sp, prefix_usage,
						lpm_tree);
	if (err)
		goto err_left_struct_set;
	return lpm_tree;

err_left_struct_set:
	mlxsw_sp_lpm_tree_free(mlxsw_sp, lpm_tree);
	return ERR_PTR(err);
}

static int mlxsw_sp_lpm_tree_destroy(struct mlxsw_sp *mlxsw_sp,
				     struct mlxsw_sp_lpm_tree *lpm_tree)
{
	return mlxsw_sp_lpm_tree_free(mlxsw_sp, lpm_tree);
}

static struct mlxsw_sp_lpm_tree *
mlxsw_sp_lpm_tree_get(struct mlxsw_sp *mlxsw_sp,
		      struct mlxsw_sp_prefix_usage *prefix_usage,
		      enum mlxsw_sp_l3proto proto)
{
	struct mlxsw_sp_lpm_tree *lpm_tree;
	int i;

	for (i = 0; i < MLXSW_SP_LPM_TREE_COUNT; i++) {
		lpm_tree = &mlxsw_sp->router.lpm_trees[i];
		if (lpm_tree->proto == proto &&
		    mlxsw_sp_prefix_usage_eq(&lpm_tree->prefix_usage,
					     prefix_usage))
			goto inc_ref_count;
	}
	lpm_tree = mlxsw_sp_lpm_tree_create(mlxsw_sp, prefix_usage, proto);
	if (IS_ERR(lpm_tree))
		return lpm_tree;

inc_ref_count:
	lpm_tree->ref_count++;
	return lpm_tree;
}

static int mlxsw_sp_lpm_tree_put(struct mlxsw_sp *mlxsw_sp,
				 struct mlxsw_sp_lpm_tree *lpm_tree)
{
	if (--lpm_tree->ref_count == 0)
		return mlxsw_sp_lpm_tree_destroy(mlxsw_sp, lpm_tree);
	return 0;
}

static void mlxsw_sp_lpm_init(struct mlxsw_sp *mlxsw_sp)
{
	struct mlxsw_sp_lpm_tree *lpm_tree;
	int i;

	for (i = 0; i < MLXSW_SP_LPM_TREE_COUNT; i++) {
		lpm_tree = &mlxsw_sp->router.lpm_trees[i];
		lpm_tree->id = i + MLXSW_SP_LPM_TREE_MIN;
	}
}

static struct mlxsw_sp_vr *mlxsw_sp_vr_find_unused(struct mlxsw_sp *mlxsw_sp)
{
	struct mlxsw_sp_vr *vr;
	int i;

	for (i = 0; i < MLXSW_SP_VIRTUAL_ROUTER_MAX; i++) {
		vr = &mlxsw_sp->router.vrs[i];
		if (!vr->used)
			return vr;
	}
	return NULL;
}

static int mlxsw_sp_vr_lpm_tree_bind(struct mlxsw_sp *mlxsw_sp,
				     struct mlxsw_sp_vr *vr)
{
	char raltb_pl[MLXSW_REG_RALTB_LEN];

	mlxsw_reg_raltb_pack(raltb_pl, vr->id, vr->proto, vr->lpm_tree->id);
	return mlxsw_reg_write(mlxsw_sp->core, MLXSW_REG(raltb), raltb_pl);
}

static int mlxsw_sp_vr_lpm_tree_unbind(struct mlxsw_sp *mlxsw_sp,
				       struct mlxsw_sp_vr *vr)
{
	char raltb_pl[MLXSW_REG_RALTB_LEN];

	/* Bind to tree 0 which is default */
	mlxsw_reg_raltb_pack(raltb_pl, vr->id, vr->proto, 0);
	return mlxsw_reg_write(mlxsw_sp->core, MLXSW_REG(raltb), raltb_pl);
}

static u32 mlxsw_sp_fix_tb_id(u32 tb_id)
{
	/* For our purpose, squash main and local table into one */
	if (tb_id == RT_TABLE_LOCAL)
		tb_id = RT_TABLE_MAIN;
	return tb_id;
}

static struct mlxsw_sp_vr *mlxsw_sp_vr_find(struct mlxsw_sp *mlxsw_sp,
					    u32 tb_id,
					    enum mlxsw_sp_l3proto proto)
{
	struct mlxsw_sp_vr *vr;
	int i;

	tb_id = mlxsw_sp_fix_tb_id(tb_id);
	for (i = 0; i < MLXSW_SP_VIRTUAL_ROUTER_MAX; i++) {
		vr = &mlxsw_sp->router.vrs[i];
		if (vr->used && vr->proto == proto && vr->tb_id == tb_id)
			return vr;
	}
	return NULL;
}

static struct mlxsw_sp_vr *mlxsw_sp_vr_create(struct mlxsw_sp *mlxsw_sp,
					      unsigned char prefix_len,
					      u32 tb_id,
					      enum mlxsw_sp_l3proto proto)
{
	struct mlxsw_sp_prefix_usage req_prefix_usage;
	struct mlxsw_sp_lpm_tree *lpm_tree;
	struct mlxsw_sp_vr *vr;
	int err;

	vr = mlxsw_sp_vr_find_unused(mlxsw_sp);
	if (!vr)
		return ERR_PTR(-EBUSY);
	vr->fib = mlxsw_sp_fib_create();
	if (IS_ERR(vr->fib))
		return ERR_CAST(vr->fib);

	vr->proto = proto;
	vr->tb_id = tb_id;
	mlxsw_sp_prefix_usage_zero(&req_prefix_usage);
	mlxsw_sp_prefix_usage_set(&req_prefix_usage, prefix_len);
	lpm_tree = mlxsw_sp_lpm_tree_get(mlxsw_sp, &req_prefix_usage, proto);
	if (IS_ERR(lpm_tree)) {
		err = PTR_ERR(lpm_tree);
		goto err_tree_get;
	}
	vr->lpm_tree = lpm_tree;
	err = mlxsw_sp_vr_lpm_tree_bind(mlxsw_sp, vr);
	if (err)
		goto err_tree_bind;

	vr->used = true;
	return vr;

err_tree_bind:
	mlxsw_sp_lpm_tree_put(mlxsw_sp, vr->lpm_tree);
err_tree_get:
	mlxsw_sp_fib_destroy(vr->fib);

	return ERR_PTR(err);
}

static void mlxsw_sp_vr_destroy(struct mlxsw_sp *mlxsw_sp,
				struct mlxsw_sp_vr *vr)
{
	mlxsw_sp_vr_lpm_tree_unbind(mlxsw_sp, vr);
	mlxsw_sp_lpm_tree_put(mlxsw_sp, vr->lpm_tree);
	mlxsw_sp_fib_destroy(vr->fib);
	vr->used = false;
}

static int
mlxsw_sp_vr_lpm_tree_check(struct mlxsw_sp *mlxsw_sp, struct mlxsw_sp_vr *vr,
			   struct mlxsw_sp_prefix_usage *req_prefix_usage)
{
	struct mlxsw_sp_lpm_tree *lpm_tree;

	if (mlxsw_sp_prefix_usage_eq(req_prefix_usage,
				     &vr->lpm_tree->prefix_usage))
		return 0;

	lpm_tree = mlxsw_sp_lpm_tree_get(mlxsw_sp, req_prefix_usage, vr->proto);
	if (IS_ERR(lpm_tree)) {
		/* We failed to get a tree according to the required
		 * prefix usage. However, the current tree might be still good
		 * for us if our requirement is subset of the prefixes used
		 * in the tree.
		 */
		if (mlxsw_sp_prefix_usage_subset(req_prefix_usage,
						 &vr->lpm_tree->prefix_usage))
			return 0;
		return PTR_ERR(lpm_tree);
	}

	mlxsw_sp_vr_lpm_tree_unbind(mlxsw_sp, vr);
	mlxsw_sp_lpm_tree_put(mlxsw_sp, vr->lpm_tree);
	vr->lpm_tree = lpm_tree;
	return mlxsw_sp_vr_lpm_tree_bind(mlxsw_sp, vr);
}

static struct mlxsw_sp_vr *mlxsw_sp_vr_get(struct mlxsw_sp *mlxsw_sp,
					   unsigned char prefix_len,
					   u32 tb_id,
					   enum mlxsw_sp_l3proto proto)
{
	struct mlxsw_sp_vr *vr;
	int err;

	tb_id = mlxsw_sp_fix_tb_id(tb_id);
	vr = mlxsw_sp_vr_find(mlxsw_sp, tb_id, proto);
	if (!vr) {
		vr = mlxsw_sp_vr_create(mlxsw_sp, prefix_len, tb_id, proto);
		if (IS_ERR(vr))
			return vr;
	} else {
		struct mlxsw_sp_prefix_usage req_prefix_usage;

		mlxsw_sp_prefix_usage_cpy(&req_prefix_usage,
					  &vr->fib->prefix_usage);
		mlxsw_sp_prefix_usage_set(&req_prefix_usage, prefix_len);
		/* Need to replace LPM tree in case new prefix is required. */
		err = mlxsw_sp_vr_lpm_tree_check(mlxsw_sp, vr,
						 &req_prefix_usage);
		if (err)
			return ERR_PTR(err);
	}
	return vr;
}

static void mlxsw_sp_vr_put(struct mlxsw_sp *mlxsw_sp, struct mlxsw_sp_vr *vr)
{
	/* Destroy virtual router entity in case the associated FIB is empty
	 * and allow it to be used for other tables in future. Otherwise,
	 * check if some prefix usage did not disappear and change tree if
	 * that is the case. Note that in case new, smaller tree cannot be
	 * allocated, the original one will be kept being used.
	 */
	if (mlxsw_sp_prefix_usage_none(&vr->fib->prefix_usage))
		mlxsw_sp_vr_destroy(mlxsw_sp, vr);
	else
		mlxsw_sp_vr_lpm_tree_check(mlxsw_sp, vr,
					   &vr->fib->prefix_usage);
}

static void mlxsw_sp_vrs_init(struct mlxsw_sp *mlxsw_sp)
{
	struct mlxsw_sp_vr *vr;
	int i;

	for (i = 0; i < MLXSW_SP_VIRTUAL_ROUTER_MAX; i++) {
		vr = &mlxsw_sp->router.vrs[i];
		vr->id = i;
	}
}

struct mlxsw_sp_neigh_key {
	unsigned char addr[sizeof(struct in6_addr)];
	struct net_device *dev;
};

struct mlxsw_sp_neigh_entry {
	struct rhash_head ht_node;
	struct mlxsw_sp_neigh_key key;
	u16 rif_id;
	struct neighbour *n;
	bool offloaded;
	struct delayed_work dw;
	unsigned char ha[ETH_ALEN];
	struct list_head nexthop_list; /* list of nexthops using
					* this neigh entry
					*/
};

static const struct rhashtable_params mlxsw_sp_neigh_ht_params = {
	.key_offset = offsetof(struct mlxsw_sp_neigh_entry, key),
	.head_offset = offsetof(struct mlxsw_sp_neigh_entry, ht_node),
	.key_len = sizeof(struct mlxsw_sp_neigh_key),
};

static int
mlxsw_sp_neigh_entry_insert(struct mlxsw_sp *mlxsw_sp,
			    struct mlxsw_sp_neigh_entry *neigh_entry)
{
	return rhashtable_insert_fast(&mlxsw_sp->router.neigh_ht,
				      &neigh_entry->ht_node,
				      mlxsw_sp_neigh_ht_params);
}

static void
mlxsw_sp_neigh_entry_remove(struct mlxsw_sp *mlxsw_sp,
			    struct mlxsw_sp_neigh_entry *neigh_entry)
{
	rhashtable_remove_fast(&mlxsw_sp->router.neigh_ht,
			       &neigh_entry->ht_node,
			       mlxsw_sp_neigh_ht_params);
}

static void mlxsw_sp_router_neigh_update_hw(struct work_struct *work);

static struct mlxsw_sp_neigh_entry *
mlxsw_sp_neigh_entry_create(const void *addr, size_t addr_len,
			    struct net_device *dev, u16 rif_id,
			    struct neighbour *n)
{
	struct mlxsw_sp_neigh_entry *neigh_entry;

	neigh_entry = kzalloc(sizeof(*neigh_entry), GFP_ATOMIC);
	if (!neigh_entry)
		return NULL;
	memcpy(neigh_entry->key.addr, addr, addr_len);
	neigh_entry->key.dev = dev;
	neigh_entry->rif_id = rif_id;
	neigh_entry->n = n;
	INIT_DELAYED_WORK(&neigh_entry->dw, mlxsw_sp_router_neigh_update_hw);
	INIT_LIST_HEAD(&neigh_entry->nexthop_list);
	return neigh_entry;
}

static void
mlxsw_sp_neigh_entry_destroy(struct mlxsw_sp_neigh_entry *neigh_entry)
{
	kfree(neigh_entry);
}

static struct mlxsw_sp_neigh_entry *
mlxsw_sp_neigh_entry_lookup(struct mlxsw_sp *mlxsw_sp, const void *addr,
			    size_t addr_len, struct net_device *dev)
{
	struct mlxsw_sp_neigh_key key = {{ 0 } };

	memcpy(key.addr, addr, addr_len);
	key.dev = dev;
	return rhashtable_lookup_fast(&mlxsw_sp->router.neigh_ht,
				      &key, mlxsw_sp_neigh_ht_params);
}

int mlxsw_sp_router_neigh_construct(struct net_device *dev,
				    struct neighbour *n)
{
	struct mlxsw_sp_port *mlxsw_sp_port = netdev_priv(dev);
	struct mlxsw_sp *mlxsw_sp = mlxsw_sp_port->mlxsw_sp;
	struct mlxsw_sp_neigh_entry *neigh_entry;
	struct mlxsw_sp_rif *rif;
	u32 dip;
	int err;

	if (n->tbl != &arp_tbl)
		return 0;

	dip = ntohl(*((__be32 *) n->primary_key));
	neigh_entry = mlxsw_sp_neigh_entry_lookup(mlxsw_sp, &dip, sizeof(dip),
						  n->dev);
	if (neigh_entry) {
		WARN_ON(neigh_entry->n != n);
		return 0;
	}

	rif = mlxsw_sp_rif_find_by_dev(mlxsw_sp, dev);
	if (WARN_ON(!rif))
		return 0;

	neigh_entry = mlxsw_sp_neigh_entry_create(&dip, sizeof(dip), n->dev,
						  rif->rif, n);
	if (!neigh_entry)
		return -ENOMEM;
	err = mlxsw_sp_neigh_entry_insert(mlxsw_sp, neigh_entry);
	if (err)
		goto err_neigh_entry_insert;
	return 0;

err_neigh_entry_insert:
	mlxsw_sp_neigh_entry_destroy(neigh_entry);
	return err;
}

void mlxsw_sp_router_neigh_destroy(struct net_device *dev,
				   struct neighbour *n)
{
	struct mlxsw_sp_port *mlxsw_sp_port = netdev_priv(dev);
	struct mlxsw_sp *mlxsw_sp = mlxsw_sp_port->mlxsw_sp;
	struct mlxsw_sp_neigh_entry *neigh_entry;
	u32 dip;

	if (n->tbl != &arp_tbl)
		return;

	dip = ntohl(*((__be32 *) n->primary_key));
	neigh_entry = mlxsw_sp_neigh_entry_lookup(mlxsw_sp, &dip, sizeof(dip),
						  n->dev);
	if (!neigh_entry)
		return;
	mlxsw_sp_neigh_entry_remove(mlxsw_sp, neigh_entry);
	mlxsw_sp_neigh_entry_destroy(neigh_entry);
}

static int mlxsw_sp_router_neigh_calc_update_time(struct mlxsw_sp *mlxsw_sp)
{
	int new_update_time = INT_MAX;
	int i;

	/* for all devices in arp_tbl, find the mlxsw offloaded device
	 * with the minimum reachable_time
	 */
	for (i = 0; i < MLXSW_SP_RIF_MAX; i++) {
		if (!mlxsw_sp->rifs[i])
			continue;
		if (new_update_time > mlxsw_sp->rifs[i]->reachable_time)
			new_update_time = mlxsw_sp->rifs[i]->reachable_time;
	}
	if (new_update_time == INT_MAX)
		new_update_time = 0;

	new_update_time = max(new_update_time / 10 * 9,
			      MLXSW_SP_ROUTER_NEIGH_MIN_UPDATE_TIME);

	return new_update_time;
}

static void mlxsw_sp_router_update_neigh(struct mlxsw_sp *mlxsw_sp,
					 u32 dip, bool a, u16 rif_id)
{
	struct mlxsw_sp_rif *rif = mlxsw_sp->rifs[rif_id];
	struct net_device *dev;
	struct neighbour *n;
	__be32 dipn = htonl(dip);

	if (!rif)
		return;
	dev = rif->dev;

	n = neigh_lookup(&arp_tbl, &dipn, dev);
	if (!n) {
		netdev_err(dev, "Neighbour %pI4h does not exist!\n", &dip);
		return;
	}
	netdev_dbg(dev, "Updating neigh dip=%pI4h, rif=%d, a=%d\n",
		   &dip, rif_id, a);
	n->used = jiffies;
	neigh_release(n);
}

static void mlxsw_sp_router_update_neighbours(struct work_struct *work)
{
	struct mlxsw_sp *mlxsw_sp = container_of(work, struct mlxsw_sp,
						 router.neigh_update_dw.work);
	int new_update_time;
	char *rauhtd_pl;
	u8 num_rec;
	int err;

	mlxsw_sp->router.last_neigh_update_time = jiffies;

	rauhtd_pl = kmalloc(MLXSW_REG_RAUHTD_LEN, GFP_KERNEL);
	if (!rauhtd_pl)
		return;

	mlxsw_reg_rauhtd_pack(rauhtd_pl, MLXSW_REG_RAUHTD_FILTER_A,
			      MLXSW_REG_RAUHTD_OP_DUMP_AND_CLEAR,
			      MLXSW_REG_RAUHTD_REC_MAX_NUM, 1,
			      MLXSW_REG_RAUHTD_ENTRY_TYPE_IPV4, 0);

	/* start rauhtd transaction */
	do {
		int ent;

		err = mlxsw_reg_write(mlxsw_sp->core, MLXSW_REG(rauhtd),
				      rauhtd_pl);
		if (err)
			goto out;

		mlxsw_reg_rauhtd_unpack(rauhtd_pl, &num_rec);

		/* foreach ipv4 entry */
		for (ent = 0; ent < num_rec; ent++) {
			u8 num_neigh;
			int neigh;

			mlxsw_reg_rauhtd_ipv4ent_unpack(rauhtd_pl, ent,
							&num_neigh);

			/* hardware returns the number substracted by 1, so
			 * update it
			 */
			num_neigh += 1;

			/* foreach neigh inside an ipv4 entry */
			for (neigh = 0; neigh < num_neigh; neigh++) {
				u16 rif_id;
				u32 dip;
				bool a;

				mlxsw_reg_rauhtd_ipv4ent_neigh_unpack(rauhtd_pl,
								      ent,
								      neigh,
								      &dip, &a,
								      &rif_id);
				mlxsw_sp_router_update_neigh(mlxsw_sp, dip, a,
							     rif_id);
			}
		}
	} while (num_rec == MLXSW_REG_RAUHTD_REC_MAX_NUM);

out:
	kfree(rauhtd_pl);
	new_update_time = mlxsw_sp_router_neigh_calc_update_time(mlxsw_sp);
	mlxsw_sp->router.neigh_update_time = new_update_time;
	mlxsw_core_schedule_dw(&mlxsw_sp->router.neigh_update_dw,
			       new_update_time);
}

static void
mlxsw_sp_nexthop_neigh_update(struct mlxsw_sp *mlxsw_sp,
			      struct mlxsw_sp_neigh_entry *neigh_entry,
			      bool removing);

static void mlxsw_sp_router_neigh_update_hw(struct work_struct *work)
{
	struct mlxsw_sp_neigh_entry *neigh_entry =
		container_of(work, struct mlxsw_sp_neigh_entry, dw.work);
	struct neighbour *n = neigh_entry->n;
	struct mlxsw_sp_port *mlxsw_sp_port;
	struct mlxsw_sp *mlxsw_sp;
	char rauht_pl[MLXSW_REG_RAUHT_LEN];
	struct net_device *dev;
	bool entry_connected;
	u8 nud_state;
	bool updating;
	bool removing;
	bool adding;
	u32 dip;
	int err;

	read_lock_bh(&n->lock);
	dip = ntohl(*((__be32 *) n->primary_key));
	memcpy(neigh_entry->ha, n->ha, sizeof(neigh_entry->ha));
	nud_state = n->nud_state;
	dev = n->dev;
	read_unlock_bh(&n->lock);

	mlxsw_sp_port = mlxsw_sp_port_dev_lower_find(n->dev);
	if (WARN_ON(!mlxsw_sp_port))
		return;
	mlxsw_sp = mlxsw_sp_port->mlxsw_sp;

	entry_connected = nud_state & NUD_VALID;
	adding = (!neigh_entry->offloaded) && entry_connected;
	updating = neigh_entry->offloaded && entry_connected;
	removing = neigh_entry->offloaded && !entry_connected;

	if (adding || updating) {
		mlxsw_reg_rauht_pack4(rauht_pl, RAUHT_WRITE_OP_ADD,
				      neigh_entry->rif_id,
				      neigh_entry->ha, dip);
		err = mlxsw_reg_write(mlxsw_sp->core,
				      MLXSW_REG(rauht), rauht_pl);
		if (err) {
			netdev_err(dev, "Could not add neigh %pI4h\n", &dip);
			neigh_entry->offloaded = false;
		} else {
			neigh_entry->offloaded = true;
		}
		mlxsw_sp_nexthop_neigh_update(mlxsw_sp, neigh_entry, false);
	} else if (removing) {
		mlxsw_reg_rauht_pack4(rauht_pl, RAUHT_WRITE_OP_DELETE,
				      neigh_entry->rif_id,
				      neigh_entry->ha, dip);
		err = mlxsw_reg_write(mlxsw_sp->core, MLXSW_REG(rauht),
				      rauht_pl);
		if (err) {
			netdev_err(dev, "Could not delete neigh %pI4h\n", &dip);
			neigh_entry->offloaded = true;
		} else {
			neigh_entry->offloaded = false;
		}
		mlxsw_sp_nexthop_neigh_update(mlxsw_sp, neigh_entry, true);
	}
}

static void
mlxsw_sp_router_neigh_modify_update_time(struct mlxsw_sp *mlxsw_sp)
{
	int new_period;
	int retroactive_period;
	int last_update_delta;

	new_period = mlxsw_sp->router.neigh_update_time;
	last_update_delta = (jiffies - mlxsw_sp->router.last_neigh_update_time)
			    * HZ / 1000;
	retroactive_period = new_period - last_update_delta;

	if (retroactive_period < 0)
		mlxsw_core_modify_dw(&mlxsw_sp->router.neigh_update_dw, 0);
	else
		mlxsw_core_modify_dw(&mlxsw_sp->router.neigh_update_dw,
				     retroactive_period);
	mlxsw_sp->router.neigh_update_time = new_period;
}

static int mlxsw_sp_router_netevent_event(struct notifier_block *unused,
					  unsigned long event, void *ptr)
{
	struct mlxsw_sp_neigh_entry *neigh_entry;
	struct mlxsw_sp_port *mlxsw_sp_port;
	struct mlxsw_sp_rif *mlxsw_rif;
	struct mlxsw_sp *mlxsw_sp;
	struct net_device *dev;
	struct neigh_parms *p;
	struct neighbour *n;
	int curr_reachable_time;
	u32 dip;

	switch (event) {
	case NETEVENT_NEIGH_UPDATE:
		n = ptr;
		dev = n->dev;

		if (n->tbl != &arp_tbl)
			return NOTIFY_DONE;

		mlxsw_sp_port = mlxsw_sp_port_dev_lower_find(dev);
		if (!mlxsw_sp_port)
			return NOTIFY_DONE;
		mlxsw_sp = mlxsw_sp_port->mlxsw_sp;

		dip = ntohl(*((__be32 *) n->primary_key));
		neigh_entry = mlxsw_sp_neigh_entry_lookup(mlxsw_sp,
							  &dip,
							  sizeof(__be32),
							  dev);
		if (WARN_ON(!neigh_entry))
			return NOTIFY_DONE;
		mlxsw_core_schedule_dw(&neigh_entry->dw, 0);
		break;
	case NETEVENT_REACHABLE_TIME_UPDATE:
		p = ptr;
		if (!p->dev)
			return NOTIFY_DONE;
		dev = p->dev;

		mlxsw_sp_port = mlxsw_sp_port_dev_lower_find(dev);
		if (!mlxsw_sp_port)
			return NOTIFY_DONE;
		mlxsw_sp = mlxsw_sp_port->mlxsw_sp;

		/* Find the specific rif and update its reachable time */
		mlxsw_rif = mlxsw_sp_rif_find_by_dev(mlxsw_sp, dev);
		if (!mlxsw_rif)
			return NOTIFY_DONE;
		mlxsw_rif->reachable_time = p->reachable_time;
		netdev_dbg(dev, "set reachable time to %dms\n",
			   mlxsw_rif->reachable_time);
		curr_reachable_time = p->reachable_time / 10 * 9;

		/* if the rif's is lower than the current reachable time,
		 * update it
		 */
		if (curr_reachable_time < mlxsw_sp->router.neigh_update_time) {
			mlxsw_sp->router.neigh_update_time = curr_reachable_time;
			mlxsw_sp_router_neigh_modify_update_time(mlxsw_sp);
		}
		break;
	}

	return NOTIFY_DONE;
}

static struct notifier_block mlxsw_sp_router_netevent_nb __read_mostly = {
	.notifier_call = mlxsw_sp_router_netevent_event,
};

static int mlxsw_sp_neigh_init(struct mlxsw_sp *mlxsw_sp)
{
	int err;

	err = rhashtable_init(&mlxsw_sp->router.neigh_ht,
			      &mlxsw_sp_neigh_ht_params);
	if (err)
		return err;

	err = register_netevent_notifier(&mlxsw_sp_router_netevent_nb);
	if (err)
		goto err_register_netevent_notifier;

	/* Create the delayed work for the activity_update */
	INIT_DELAYED_WORK(&mlxsw_sp->router.neigh_update_dw,
			  mlxsw_sp_router_update_neighbours);
	mlxsw_core_schedule_dw(&mlxsw_sp->router.neigh_update_dw, 0);
	return 0;

err_register_netevent_notifier:
	unregister_netevent_notifier(&mlxsw_sp_router_netevent_nb);
	return err;
}

static void mlxsw_sp_neigh_fini(struct mlxsw_sp *mlxsw_sp)
{
	cancel_delayed_work_sync(&mlxsw_sp->router.neigh_update_dw);
	unregister_netevent_notifier(&mlxsw_sp_router_netevent_nb);
	rhashtable_destroy(&mlxsw_sp->router.neigh_ht);
}

struct mlxsw_sp_nexthop {
	struct list_head neigh_list_node; /* member of neigh entry list */
	struct mlxsw_sp_nexthop_group *nh_grp; /* pointer back to the group
						* this belongs to
						*/
	u8 should_offload:1, /* set indicates this neigh is connected and
			      * should be put to KVD linear area of this group.
			      */
	   offloaded:1, /* set in case the neigh is actually put into
			 * KVD linear area of this group.
			 */
	   update:1; /* set indicates that MAC of this neigh should be
		      * updated in HW
		      */
	struct mlxsw_sp_neigh_entry *neigh_entry;
};

struct mlxsw_sp_nexthop_group {
	struct list_head list; /* node in mlxsw->router.nexthop_group_list */
	struct list_head fib_list; /* list of fib entries that use this group */
	u8 adj_index_valid:1;
	u32 adj_index;
	u16 ecmp_size;
	u16 count;
	struct mlxsw_sp_nexthop nexthops[0];
};

static int mlxsw_sp_adj_index_mass_update_vr(struct mlxsw_sp *mlxsw_sp,
					     struct mlxsw_sp_vr *vr,
					     u32 adj_index, u16 ecmp_size,
					     u32 new_adj_index,
					     u16 new_ecmp_size)
{
	char raleu_pl[MLXSW_REG_RALEU_LEN];

	mlxsw_reg_raleu_pack(raleu_pl, vr->proto, vr->id,
			     adj_index, ecmp_size,
			     new_adj_index, new_ecmp_size);
	return mlxsw_reg_write(mlxsw_sp->core, MLXSW_REG(raleu), raleu_pl);
}

static int mlxsw_sp_adj_index_mass_update(struct mlxsw_sp *mlxsw_sp,
					  struct mlxsw_sp_nexthop_group *nh_grp,
					  u32 old_adj_index, u16 old_ecmp_size)
{
	struct mlxsw_sp_fib_entry *fib_entry;
	struct mlxsw_sp_vr *vr = NULL;
	int err;

	list_for_each_entry(fib_entry, &nh_grp->fib_list, nexthop_group_node) {
		if (vr == fib_entry->vr)
			continue;
		vr = fib_entry->vr;
		err = mlxsw_sp_adj_index_mass_update_vr(mlxsw_sp, vr,
							old_adj_index,
							old_ecmp_size,
							nh_grp->adj_index,
							nh_grp->ecmp_size);
		if (err)
			return err;
	}
	return 0;
}

static int mlxsw_sp_nexthop_mac_update(struct mlxsw_sp *mlxsw_sp, u32 adj_index,
				       struct mlxsw_sp_nexthop *nh)
{
	struct mlxsw_sp_neigh_entry *neigh_entry = nh->neigh_entry;
	char ratr_pl[MLXSW_REG_RATR_LEN];

	mlxsw_reg_ratr_pack(ratr_pl, MLXSW_REG_RATR_OPCODE_WRITE_ENTRY,
			    true, adj_index, neigh_entry->rif_id);
	mlxsw_reg_ratr_eth_entry_pack(ratr_pl, neigh_entry->ha);
	return mlxsw_reg_write(mlxsw_sp->core, MLXSW_REG(ratr), ratr_pl);
}

static int
mlxsw_sp_nexthop_group_mac_update(struct mlxsw_sp *mlxsw_sp,
				  struct mlxsw_sp_nexthop_group *nh_grp)
{
	u32 adj_index = nh_grp->adj_index; /* base */
	struct mlxsw_sp_nexthop *nh;
	int i;
	int err;

	for (i = 0; i < nh_grp->count; i++) {
		nh = &nh_grp->nexthops[i];

		if (!nh->should_offload) {
			nh->offloaded = 0;
			continue;
		}

		if (nh->update) {
			err = mlxsw_sp_nexthop_mac_update(mlxsw_sp,
							  adj_index, nh);
			if (err)
				return err;
			nh->update = 0;
			nh->offloaded = 1;
		}
		adj_index++;
	}
	return 0;
}

static int mlxsw_sp_fib_entry_update(struct mlxsw_sp *mlxsw_sp,
				     struct mlxsw_sp_fib_entry *fib_entry);

static int
mlxsw_sp_nexthop_fib_entries_update(struct mlxsw_sp *mlxsw_sp,
				    struct mlxsw_sp_nexthop_group *nh_grp)
{
	struct mlxsw_sp_fib_entry *fib_entry;
	int err;

	list_for_each_entry(fib_entry, &nh_grp->fib_list, nexthop_group_node) {
		err = mlxsw_sp_fib_entry_update(mlxsw_sp, fib_entry);
		if (err)
			return err;
	}
	return 0;
}

static void
mlxsw_sp_nexthop_group_refresh(struct mlxsw_sp *mlxsw_sp,
			       struct mlxsw_sp_nexthop_group *nh_grp)
{
	struct mlxsw_sp_nexthop *nh;
	bool offload_change = false;
	u32 adj_index;
	u16 ecmp_size = 0;
	bool old_adj_index_valid;
	u32 old_adj_index;
	u16 old_ecmp_size;
	int ret;
	int i;
	int err;

	for (i = 0; i < nh_grp->count; i++) {
		nh = &nh_grp->nexthops[i];

		if (nh->should_offload ^ nh->offloaded) {
			offload_change = true;
			if (nh->should_offload)
				nh->update = 1;
		}
		if (nh->should_offload)
			ecmp_size++;
	}
	if (!offload_change) {
		/* Nothing was added or removed, so no need to reallocate. Just
		 * update MAC on existing adjacency indexes.
		 */
		err = mlxsw_sp_nexthop_group_mac_update(mlxsw_sp, nh_grp);
		if (err) {
			dev_warn(mlxsw_sp->bus_info->dev, "Failed to update neigh MAC in adjacency table.\n");
			goto set_trap;
		}
		return;
	}
	if (!ecmp_size)
		/* No neigh of this group is connected so we just set
		 * the trap and let everthing flow through kernel.
		 */
		goto set_trap;

	ret = mlxsw_sp_kvdl_alloc(mlxsw_sp, ecmp_size);
	if (ret < 0) {
		/* We ran out of KVD linear space, just set the
		 * trap and let everything flow through kernel.
		 */
		dev_warn(mlxsw_sp->bus_info->dev, "Failed to allocate KVD linear area for nexthop group.\n");
		goto set_trap;
	}
	adj_index = ret;
	old_adj_index_valid = nh_grp->adj_index_valid;
	old_adj_index = nh_grp->adj_index;
	old_ecmp_size = nh_grp->ecmp_size;
	nh_grp->adj_index_valid = 1;
	nh_grp->adj_index = adj_index;
	nh_grp->ecmp_size = ecmp_size;
	err = mlxsw_sp_nexthop_group_mac_update(mlxsw_sp, nh_grp);
	if (err) {
		dev_warn(mlxsw_sp->bus_info->dev, "Failed to update neigh MAC in adjacency table.\n");
		goto set_trap;
	}

	if (!old_adj_index_valid) {
		/* The trap was set for fib entries, so we have to call
		 * fib entry update to unset it and use adjacency index.
		 */
		err = mlxsw_sp_nexthop_fib_entries_update(mlxsw_sp, nh_grp);
		if (err) {
			dev_warn(mlxsw_sp->bus_info->dev, "Failed to add adjacency index to fib entries.\n");
			goto set_trap;
		}
		return;
	}

	err = mlxsw_sp_adj_index_mass_update(mlxsw_sp, nh_grp,
					     old_adj_index, old_ecmp_size);
	mlxsw_sp_kvdl_free(mlxsw_sp, old_adj_index);
	if (err) {
		dev_warn(mlxsw_sp->bus_info->dev, "Failed to mass-update adjacency index for nexthop group.\n");
		goto set_trap;
	}
	return;

set_trap:
	old_adj_index_valid = nh_grp->adj_index_valid;
	nh_grp->adj_index_valid = 0;
	for (i = 0; i < nh_grp->count; i++) {
		nh = &nh_grp->nexthops[i];
		nh->offloaded = 0;
	}
	err = mlxsw_sp_nexthop_fib_entries_update(mlxsw_sp, nh_grp);
	if (err)
		dev_warn(mlxsw_sp->bus_info->dev, "Failed to set traps for fib entries.\n");
	if (old_adj_index_valid)
		mlxsw_sp_kvdl_free(mlxsw_sp, nh_grp->adj_index);
}

static void __mlxsw_sp_nexthop_neigh_update(struct mlxsw_sp_nexthop *nh,
					    bool removing)
{
	if (!removing && !nh->should_offload)
		nh->should_offload = 1;
	else if (removing && nh->offloaded)
		nh->should_offload = 0;
	nh->update = 1;
}

static void
mlxsw_sp_nexthop_neigh_update(struct mlxsw_sp *mlxsw_sp,
			      struct mlxsw_sp_neigh_entry *neigh_entry,
			      bool removing)
{
	struct mlxsw_sp_nexthop *nh;

	list_for_each_entry(nh, &neigh_entry->nexthop_list,
			    neigh_list_node) {
		__mlxsw_sp_nexthop_neigh_update(nh, removing);
		mlxsw_sp_nexthop_group_refresh(mlxsw_sp, nh->nh_grp);
	}
}

static int mlxsw_sp_nexthop_init(struct mlxsw_sp *mlxsw_sp,
				 struct mlxsw_sp_nexthop_group *nh_grp,
				 struct mlxsw_sp_nexthop *nh,
				 struct fib_nh *fib_nh)
{
	struct mlxsw_sp_neigh_entry *neigh_entry;
	u32 gwip = ntohl(fib_nh->nh_gw);
	struct net_device *dev = fib_nh->nh_dev;
	struct neighbour *n;
	u8 nud_state;

	neigh_entry = mlxsw_sp_neigh_entry_lookup(mlxsw_sp, &gwip,
						  sizeof(gwip), dev);
	if (!neigh_entry) {
		__be32 gwipn = htonl(gwip);

		n = neigh_create(&arp_tbl, &gwipn, dev);
		if (IS_ERR(n))
			return PTR_ERR(n);
		neigh_event_send(n, NULL);
		neigh_release(n);
		neigh_entry = mlxsw_sp_neigh_entry_lookup(mlxsw_sp, &gwip,
							  sizeof(gwip), dev);
		if (!neigh_entry)
			return -EINVAL;
	}
	nh->nh_grp = nh_grp;
	nh->neigh_entry = neigh_entry;
	list_add_tail(&nh->neigh_list_node, &neigh_entry->nexthop_list);
	n = neigh_entry->n;
	read_lock_bh(&n->lock);
	nud_state = n->nud_state;
	read_unlock_bh(&n->lock);
	__mlxsw_sp_nexthop_neigh_update(nh, !(nud_state & NUD_VALID));

	return 0;
}

static void mlxsw_sp_nexthop_fini(struct mlxsw_sp *mlxsw_sp,
				  struct mlxsw_sp_nexthop *nh)
{
	list_del(&nh->neigh_list_node);
}

static struct mlxsw_sp_nexthop_group *
mlxsw_sp_nexthop_group_create(struct mlxsw_sp *mlxsw_sp, struct fib_info *fi)
{
	struct mlxsw_sp_nexthop_group *nh_grp;
	struct mlxsw_sp_nexthop *nh;
	struct fib_nh *fib_nh;
	size_t alloc_size;
	int i;
	int err;

	alloc_size = sizeof(*nh_grp) +
		     fi->fib_nhs * sizeof(struct mlxsw_sp_nexthop);
	nh_grp = kzalloc(alloc_size, GFP_KERNEL);
	if (!nh_grp)
		return ERR_PTR(-ENOMEM);
	INIT_LIST_HEAD(&nh_grp->fib_list);
	nh_grp->count = fi->fib_nhs;
	for (i = 0; i < nh_grp->count; i++) {
		nh = &nh_grp->nexthops[i];
		fib_nh = &fi->fib_nh[i];
		err = mlxsw_sp_nexthop_init(mlxsw_sp, nh_grp, nh, fib_nh);
		if (err)
			goto err_nexthop_init;
	}
	list_add_tail(&nh_grp->list, &mlxsw_sp->router.nexthop_group_list);
	mlxsw_sp_nexthop_group_refresh(mlxsw_sp, nh_grp);
	return nh_grp;

err_nexthop_init:
	kfree(nh_grp);
	return ERR_PTR(err);
}

static void
mlxsw_sp_nexthop_group_destroy(struct mlxsw_sp *mlxsw_sp,
			       struct mlxsw_sp_nexthop_group *nh_grp)
{
	struct mlxsw_sp_nexthop *nh;
	int i;

	list_del(&nh_grp->list);
	for (i = 0; i < nh_grp->count; i++) {
		nh = &nh_grp->nexthops[i];
		mlxsw_sp_nexthop_fini(mlxsw_sp, nh);
	}
	kfree(nh_grp);
}

static bool mlxsw_sp_nexthop_match(struct mlxsw_sp_nexthop *nh,
				   struct fib_nh *fib_nh)
{
	u32 gwip = ntohl(fib_nh->nh_gw);

	if (memcmp(nh->neigh_entry->key.addr, &gwip, sizeof(u32)))
		return false;
	if (nh->neigh_entry->key.dev != fib_nh->nh_dev)
		return false;
	return true;
}

static bool mlxsw_sp_nexthop_group_match(struct mlxsw_sp_nexthop_group *nh_grp,
					 struct fib_info *fi)
{
	int i;
	int j;

	if (nh_grp->count != fi->fib_nhs)
		return false;
	for (i = 0; i < nh_grp->count; i++) {
		struct mlxsw_sp_nexthop *nh = &nh_grp->nexthops[i];

		for (j = 0; j < fi->fib_nhs; j++) {
			struct fib_nh *fib_nh = &fi->fib_nh[j];

			if (!mlxsw_sp_nexthop_match(nh, fib_nh))
				return false;
		}
	}
	return true;
}

static struct mlxsw_sp_nexthop_group *
mlxsw_sp_nexthop_group_find(struct mlxsw_sp *mlxsw_sp, struct fib_info *fi)
{
	struct mlxsw_sp_nexthop_group *nh_grp;

	list_for_each_entry(nh_grp, &mlxsw_sp->router.nexthop_group_list,
			    list) {
		if (mlxsw_sp_nexthop_group_match(nh_grp, fi))
			return nh_grp;
	}
	return NULL;
}

static int mlxsw_sp_nexthop_group_get(struct mlxsw_sp *mlxsw_sp,
				      struct mlxsw_sp_fib_entry *fib_entry,
				      struct fib_info *fi)
{
	struct mlxsw_sp_nexthop_group *nh_grp;

	nh_grp = mlxsw_sp_nexthop_group_find(mlxsw_sp, fi);
	if (!nh_grp) {
		nh_grp = mlxsw_sp_nexthop_group_create(mlxsw_sp, fi);
		if (IS_ERR(nh_grp))
			return PTR_ERR(nh_grp);
	}
	list_add_tail(&fib_entry->nexthop_group_node, &nh_grp->fib_list);
	fib_entry->nh_group = nh_grp;
	return 0;
}

static void mlxsw_sp_nexthop_group_put(struct mlxsw_sp *mlxsw_sp,
				       struct mlxsw_sp_fib_entry *fib_entry)
{
	struct mlxsw_sp_nexthop_group *nh_grp = fib_entry->nh_group;

	list_del(&fib_entry->nexthop_group_node);
	if (!list_empty(&nh_grp->fib_list))
		return;
	mlxsw_sp_nexthop_group_destroy(mlxsw_sp, nh_grp);
}

static int __mlxsw_sp_router_init(struct mlxsw_sp *mlxsw_sp)
{
	char rgcr_pl[MLXSW_REG_RGCR_LEN];

	mlxsw_reg_rgcr_pack(rgcr_pl, true);
	mlxsw_reg_rgcr_max_router_interfaces_set(rgcr_pl, MLXSW_SP_RIF_MAX);
	return mlxsw_reg_write(mlxsw_sp->core, MLXSW_REG(rgcr), rgcr_pl);
}

static void __mlxsw_sp_router_fini(struct mlxsw_sp *mlxsw_sp)
{
	char rgcr_pl[MLXSW_REG_RGCR_LEN];

	mlxsw_reg_rgcr_pack(rgcr_pl, false);
	mlxsw_reg_write(mlxsw_sp->core, MLXSW_REG(rgcr), rgcr_pl);
}

int mlxsw_sp_router_init(struct mlxsw_sp *mlxsw_sp)
{
	int err;

	INIT_LIST_HEAD(&mlxsw_sp->router.nexthop_group_list);
	err = __mlxsw_sp_router_init(mlxsw_sp);
	if (err)
		return err;
	mlxsw_sp_lpm_init(mlxsw_sp);
	mlxsw_sp_vrs_init(mlxsw_sp);
	return mlxsw_sp_neigh_init(mlxsw_sp);
}

void mlxsw_sp_router_fini(struct mlxsw_sp *mlxsw_sp)
{
	mlxsw_sp_neigh_fini(mlxsw_sp);
	__mlxsw_sp_router_fini(mlxsw_sp);
}

static int mlxsw_sp_fib_entry_op4_remote(struct mlxsw_sp *mlxsw_sp,
					 struct mlxsw_sp_fib_entry *fib_entry,
					 enum mlxsw_reg_ralue_op op)
{
	char ralue_pl[MLXSW_REG_RALUE_LEN];
	u32 *p_dip = (u32 *) fib_entry->key.addr;
	struct mlxsw_sp_vr *vr = fib_entry->vr;
	enum mlxsw_reg_ralue_trap_action trap_action;
	u16 trap_id = 0;
	u32 adjacency_index = 0;
	u16 ecmp_size = 0;

	/* In case the nexthop group adjacency index is valid, use it
	 * with provided ECMP size. Otherwise, setup trap and pass
	 * traffic to kernel.
	 */
	if (fib_entry->nh_group->adj_index_valid) {
		trap_action = MLXSW_REG_RALUE_TRAP_ACTION_NOP;
		adjacency_index = fib_entry->nh_group->adj_index;
		ecmp_size = fib_entry->nh_group->ecmp_size;
	} else {
		trap_action = MLXSW_REG_RALUE_TRAP_ACTION_TRAP;
		trap_id = MLXSW_TRAP_ID_RTR_INGRESS0;
	}

	mlxsw_reg_ralue_pack4(ralue_pl, vr->proto, op, vr->id,
			      fib_entry->key.prefix_len, *p_dip);
	mlxsw_reg_ralue_act_remote_pack(ralue_pl, trap_action, trap_id,
					adjacency_index, ecmp_size);
	return mlxsw_reg_write(mlxsw_sp->core, MLXSW_REG(ralue), ralue_pl);
}

static int mlxsw_sp_fib_entry_op4_local(struct mlxsw_sp *mlxsw_sp,
					struct mlxsw_sp_fib_entry *fib_entry,
					enum mlxsw_reg_ralue_op op)
{
	char ralue_pl[MLXSW_REG_RALUE_LEN];
	u32 *p_dip = (u32 *) fib_entry->key.addr;
	struct mlxsw_sp_vr *vr = fib_entry->vr;

	mlxsw_reg_ralue_pack4(ralue_pl, vr->proto, op, vr->id,
			      fib_entry->key.prefix_len, *p_dip);
	mlxsw_reg_ralue_act_local_pack(ralue_pl,
				       MLXSW_REG_RALUE_TRAP_ACTION_NOP, 0,
				       fib_entry->rif_id);
	return mlxsw_reg_write(mlxsw_sp->core, MLXSW_REG(ralue), ralue_pl);
}

static int mlxsw_sp_fib_entry_op4_trap(struct mlxsw_sp *mlxsw_sp,
				       struct mlxsw_sp_fib_entry *fib_entry,
				       enum mlxsw_reg_ralue_op op)
{
	char ralue_pl[MLXSW_REG_RALUE_LEN];
	u32 *p_dip = (u32 *) fib_entry->key.addr;
	struct mlxsw_sp_vr *vr = fib_entry->vr;

	mlxsw_reg_ralue_pack4(ralue_pl, vr->proto, op, vr->id,
			      fib_entry->key.prefix_len, *p_dip);
	mlxsw_reg_ralue_act_ip2me_pack(ralue_pl);
	return mlxsw_reg_write(mlxsw_sp->core, MLXSW_REG(ralue), ralue_pl);
}

static int mlxsw_sp_fib_entry_op4(struct mlxsw_sp *mlxsw_sp,
				  struct mlxsw_sp_fib_entry *fib_entry,
				  enum mlxsw_reg_ralue_op op)
{
	switch (fib_entry->type) {
	case MLXSW_SP_FIB_ENTRY_TYPE_REMOTE:
		return mlxsw_sp_fib_entry_op4_remote(mlxsw_sp, fib_entry, op);
	case MLXSW_SP_FIB_ENTRY_TYPE_LOCAL:
		return mlxsw_sp_fib_entry_op4_local(mlxsw_sp, fib_entry, op);
	case MLXSW_SP_FIB_ENTRY_TYPE_TRAP:
		return mlxsw_sp_fib_entry_op4_trap(mlxsw_sp, fib_entry, op);
	}
	return -EINVAL;
}

static int mlxsw_sp_fib_entry_op(struct mlxsw_sp *mlxsw_sp,
				 struct mlxsw_sp_fib_entry *fib_entry,
				 enum mlxsw_reg_ralue_op op)
{
	switch (fib_entry->vr->proto) {
	case MLXSW_SP_L3_PROTO_IPV4:
		return mlxsw_sp_fib_entry_op4(mlxsw_sp, fib_entry, op);
	case MLXSW_SP_L3_PROTO_IPV6:
		return -EINVAL;
	}
	return -EINVAL;
}

static int mlxsw_sp_fib_entry_update(struct mlxsw_sp *mlxsw_sp,
				     struct mlxsw_sp_fib_entry *fib_entry)
{
	enum mlxsw_reg_ralue_op op;

	op = !fib_entry->added ? MLXSW_REG_RALUE_OP_WRITE_WRITE :
				 MLXSW_REG_RALUE_OP_WRITE_UPDATE;
	return mlxsw_sp_fib_entry_op(mlxsw_sp, fib_entry, op);
}

static int mlxsw_sp_fib_entry_del(struct mlxsw_sp *mlxsw_sp,
				  struct mlxsw_sp_fib_entry *fib_entry)
{
	return mlxsw_sp_fib_entry_op(mlxsw_sp, fib_entry,
				     MLXSW_REG_RALUE_OP_WRITE_DELETE);
}

struct mlxsw_sp_router_fib4_add_info {
	struct switchdev_trans_item tritem;
	struct mlxsw_sp *mlxsw_sp;
	struct mlxsw_sp_fib_entry *fib_entry;
};

static void mlxsw_sp_router_fib4_add_info_destroy(void const *data)
{
	const struct mlxsw_sp_router_fib4_add_info *info = data;
	struct mlxsw_sp_fib_entry *fib_entry = info->fib_entry;
	struct mlxsw_sp *mlxsw_sp = info->mlxsw_sp;

	mlxsw_sp_fib_entry_destroy(fib_entry);
	mlxsw_sp_vr_put(mlxsw_sp, fib_entry->vr);
	kfree(info);
}

static int
mlxsw_sp_router_fib4_entry_init(struct mlxsw_sp *mlxsw_sp,
				const struct switchdev_obj_ipv4_fib *fib4,
				struct mlxsw_sp_fib_entry *fib_entry)
{
	struct fib_info *fi = fib4->fi;

	if (fib4->type == RTN_LOCAL || fib4->type == RTN_BROADCAST) {
		fib_entry->type = MLXSW_SP_FIB_ENTRY_TYPE_TRAP;
		return 0;
	}
	if (fib4->type != RTN_UNICAST)
		return -EINVAL;

	if (fi->fib_scope != RT_SCOPE_UNIVERSE) {
		struct mlxsw_sp_rif *rif;

		fib_entry->type = MLXSW_SP_FIB_ENTRY_TYPE_LOCAL;
		rif = mlxsw_sp_rif_find_by_dev(mlxsw_sp, fi->fib_dev);
		if (!rif)
			return -EINVAL;
		fib_entry->rif_id = rif->rif;
		return 0;
	}
	fib_entry->type = MLXSW_SP_FIB_ENTRY_TYPE_REMOTE;
	return mlxsw_sp_nexthop_group_get(mlxsw_sp, fib_entry, fi);
}

static void
mlxsw_sp_router_fib4_entry_fini(struct mlxsw_sp *mlxsw_sp,
				struct mlxsw_sp_fib_entry *fib_entry)
{
	if (fib_entry->type != MLXSW_SP_FIB_ENTRY_TYPE_REMOTE)
		return;
	mlxsw_sp_nexthop_group_put(mlxsw_sp, fib_entry);
}

static int
mlxsw_sp_router_fib4_add_prepare(struct mlxsw_sp_port *mlxsw_sp_port,
				 const struct switchdev_obj_ipv4_fib *fib4,
				 struct switchdev_trans *trans)
{
	struct mlxsw_sp *mlxsw_sp = mlxsw_sp_port->mlxsw_sp;
	struct mlxsw_sp_router_fib4_add_info *info;
	struct mlxsw_sp_fib_entry *fib_entry;
	struct mlxsw_sp_vr *vr;
	int err;

	vr = mlxsw_sp_vr_get(mlxsw_sp, fib4->dst_len, fib4->tb_id,
			     MLXSW_SP_L3_PROTO_IPV4);
	if (IS_ERR(vr))
		return PTR_ERR(vr);

	fib_entry = mlxsw_sp_fib_entry_create(vr->fib, &fib4->dst,
					      sizeof(fib4->dst), fib4->dst_len);
	if (!fib_entry) {
		err = -ENOMEM;
		goto err_fib_entry_create;
	}
	fib_entry->vr = vr;

	err = mlxsw_sp_router_fib4_entry_init(mlxsw_sp, fib4, fib_entry);
	if (err)
		goto err_fib4_entry_init;

	info = kmalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		err = -ENOMEM;
		goto err_alloc_info;
	}
	info->mlxsw_sp = mlxsw_sp;
	info->fib_entry = fib_entry;
	switchdev_trans_item_enqueue(trans, info,
				     mlxsw_sp_router_fib4_add_info_destroy,
				     &info->tritem);
	return 0;

err_alloc_info:
err_fib4_entry_init:
	mlxsw_sp_fib_entry_destroy(fib_entry);
err_fib_entry_create:
	mlxsw_sp_vr_put(mlxsw_sp, vr);
	return err;
}

static int
mlxsw_sp_router_fib4_add_commit(struct mlxsw_sp_port *mlxsw_sp_port,
				const struct switchdev_obj_ipv4_fib *fib4,
				struct switchdev_trans *trans)
{
	struct mlxsw_sp *mlxsw_sp = mlxsw_sp_port->mlxsw_sp;
	struct mlxsw_sp_router_fib4_add_info *info;
	struct mlxsw_sp_fib_entry *fib_entry;
	struct mlxsw_sp_vr *vr;
	int err;

	info = switchdev_trans_item_dequeue(trans);
	fib_entry = info->fib_entry;
	kfree(info);

	vr = fib_entry->vr;
	err = mlxsw_sp_fib_entry_insert(fib_entry->vr->fib, fib_entry);
	if (err)
		goto err_fib_entry_insert;
	err = mlxsw_sp_fib_entry_update(mlxsw_sp, fib_entry);
	if (err)
		goto err_fib_entry_add;
	return 0;

err_fib_entry_add:
	mlxsw_sp_fib_entry_remove(vr->fib, fib_entry);
err_fib_entry_insert:
	mlxsw_sp_router_fib4_entry_fini(mlxsw_sp, fib_entry);
	mlxsw_sp_fib_entry_destroy(fib_entry);
	mlxsw_sp_vr_put(mlxsw_sp, vr);
	return err;
}

int mlxsw_sp_router_fib4_add(struct mlxsw_sp_port *mlxsw_sp_port,
			     const struct switchdev_obj_ipv4_fib *fib4,
			     struct switchdev_trans *trans)
{
	if (switchdev_trans_ph_prepare(trans))
		return mlxsw_sp_router_fib4_add_prepare(mlxsw_sp_port,
							fib4, trans);
	return mlxsw_sp_router_fib4_add_commit(mlxsw_sp_port,
					       fib4, trans);
}

int mlxsw_sp_router_fib4_del(struct mlxsw_sp_port *mlxsw_sp_port,
			     const struct switchdev_obj_ipv4_fib *fib4)
{
	struct mlxsw_sp *mlxsw_sp = mlxsw_sp_port->mlxsw_sp;
	struct mlxsw_sp_fib_entry *fib_entry;
	struct mlxsw_sp_vr *vr;

	vr = mlxsw_sp_vr_find(mlxsw_sp, fib4->tb_id, MLXSW_SP_L3_PROTO_IPV4);
	if (!vr) {
		dev_warn(mlxsw_sp->bus_info->dev, "Failed to find virtual router for FIB4 entry being removed.\n");
		return -ENOENT;
	}
	fib_entry = mlxsw_sp_fib_entry_lookup(vr->fib, &fib4->dst,
					      sizeof(fib4->dst), fib4->dst_len);
	if (!fib_entry) {
		dev_warn(mlxsw_sp->bus_info->dev, "Failed to find FIB4 entry being removed.\n");
		return PTR_ERR(vr);
	}
	mlxsw_sp_fib_entry_del(mlxsw_sp_port->mlxsw_sp, fib_entry);
	mlxsw_sp_fib_entry_remove(vr->fib, fib_entry);
	mlxsw_sp_router_fib4_entry_fini(mlxsw_sp, fib_entry);
	mlxsw_sp_fib_entry_destroy(fib_entry);
	mlxsw_sp_vr_put(mlxsw_sp, vr);
	return 0;
}
