/*
 * AppArmor security module
 *
 * This file contains AppArmor dfa based regular expression matching engine
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/err.h>

#include "include/match.h"

static void free_table(struct table_header *table)
{
	if (is_vmalloc_addr(table))
		vfree(table);
	else
		kfree(table);
}

static struct table_header *unpack_table(void *blob, size_t bsize)
{
	struct table_header *table = NULL;
	struct table_header th;
	size_t tsize;

	if (bsize < sizeof(struct table_header))
		goto out;

	/* loaded td_id's start at 1, subtract 1 now to avoid doing
	 * it every time we use td_id as an index
	 */
	th.td_id = be16_to_cpu(*(u16 *) (blob)) - 1;
	th.td_flags = be16_to_cpu(*(u16 *) (blob + 2));
	th.td_lolen = be32_to_cpu(*(u32 *) (blob + 8));
	blob += sizeof(struct table_header);

	if (!(th.td_flags == YYTD_DATA16 || th.td_flags == YYTD_DATA32 ||
	      th.td_flags == YYTD_DATA8))
		goto out;

	tsize = table_size(th.td_lolen, th.td_flags);
	if (bsize < tsize)
		goto out;

	/* freed by free_table */
	table = kmalloc(tsize, GFP_KERNEL);
	if (!table)
		table = vmalloc(tsize);
	if (table) {
		*table = th;
		if (th.td_flags == YYTD_DATA8)
			UNPACK_ARRAY(table->td_data, blob, th.td_lolen,
				     u8, byte_to_byte);
		else if (th.td_flags == YYTD_DATA16)
			UNPACK_ARRAY(table->td_data, blob, th.td_lolen,
				     u16, be16_to_cpu);
		else
			UNPACK_ARRAY(table->td_data, blob, th.td_lolen,
				     u32, be32_to_cpu);
	}

out:
	return table;
}

/**
 * verify_dfa - verify that all the transitions and states in the dfa tables
 *              are in bounds.
 * @dfa: dfa to test
 * @flags: flags controlling what type of accept table are acceptable
 *
 * assumes dfa has gone through the verification done by unpacking
 */
static int verify_dfa(struct aa_dfa *dfa, int flags)
{
	size_t i, state_count, trans_count;
	int error = -EPROTO;

	/* check that required tables exist */
	if (!(dfa->tables[YYTD_ID_DEF] &&
	      dfa->tables[YYTD_ID_BASE] &&
	      dfa->tables[YYTD_ID_NXT] && dfa->tables[YYTD_ID_CHK]))
		goto out;

	/* accept.size == default.size == base.size */
	state_count = dfa->tables[YYTD_ID_BASE]->td_lolen;
	if (ACCEPT1_FLAGS(flags)) {
		if (!dfa->tables[YYTD_ID_ACCEPT])
			goto out;
		if (state_count != dfa->tables[YYTD_ID_ACCEPT]->td_lolen)
			goto out;
	}
	if (ACCEPT2_FLAGS(flags)) {
		if (!dfa->tables[YYTD_ID_ACCEPT2])
			goto out;
		if (state_count != dfa->tables[YYTD_ID_ACCEPT2]->td_lolen)
			goto out;
	}
	if (state_count != dfa->tables[YYTD_ID_DEF]->td_lolen)
		goto out;

	/* next.size == chk.size */
	trans_count = dfa->tables[YYTD_ID_NXT]->td_lolen;
	if (trans_count != dfa->tables[YYTD_ID_CHK]->td_lolen)
		goto out;

	/* if equivalence classes then its table size must be 256 */
	if (dfa->tables[YYTD_ID_EC] &&
	    dfa->tables[YYTD_ID_EC]->td_lolen != 256)
		goto out;

	if (flags & DFA_FLAG_VERIFY_STATES) {
		for (i = 0; i < state_count; i++) {
			if (DEFAULT_TABLE(dfa)[i] >= state_count)
				goto out;
			if (BASE_TABLE(dfa)[i] >= trans_count + 256)
				goto out;
		}

		for (i = 0; i < trans_count; i++) {
			if (NEXT_TABLE(dfa)[i] >= state_count)
				goto out;
			if (CHECK_TABLE(dfa)[i] >= state_count)
				goto out;
		}
	}

	error = 0;
out:
	return error;
}

/**
 * aa_dfa_unpack - unpack the binary tables of a serialized dfa
 * @blob: aligned serialized stream of data to unpack
 * @size: size of data to unpack
 * @flags: flags controlling what type of accept tables are acceptable
 *
 * Unpack a dfa that has been serialized.  Dfa format and information in
 * Documentation/AppArmor/dfa.txt
 * Assumes the dfa @blob stream has been aligned on a 8 byte boundry
 *
 * Returns: an unpacked dfa ready for matching or ERR_PTR on failure
 */
struct aa_dfa *aa_dfa_unpack(void *blob, size_t size, int flags)
{
	int hsize;
	int error = -ENOMEM;
	struct aa_dfa *dfa = kzalloc(sizeof(struct aa_dfa), GFP_KERNEL);
	if (!dfa)
		goto fail;

	/* get dfa table set header */
	if (size < sizeof(struct table_set_header))
		goto fail;

	if (ntohl(*(u32 *) blob) != YYTH_MAGIC)
		goto fail;

	hsize = ntohl(*(u32 *) (blob + 4));
	if (size < hsize)
		goto fail;

	blob += hsize;
	size -= hsize;

	error = -EPROTO;
	while (size > 0) {
		struct table_header *table;
		table = unpack_table(blob, size);
		if (!table)
			goto fail;

		switch (table->td_id) {
		case YYTD_ID_ACCEPT:
			if (!(table->td_flags & ACCEPT1_FLAGS(flags)))
				goto fail;
			break;
		case YYTD_ID_ACCEPT2:
			if (!(table->td_flags & ACCEPT2_FLAGS(flags)))
				goto fail;
			break;
		case YYTD_ID_BASE:
			if (table->td_flags != YYTD_DATA32)
				goto fail;
			break;
		case YYTD_ID_DEF:
		case YYTD_ID_NXT:
		case YYTD_ID_CHK:
			if (table->td_flags != YYTD_DATA16)
				goto fail;
			break;
		case YYTD_ID_EC:
			if (table->td_flags != YYTD_DATA8)
				goto fail;
			break;
		default:
			free_table(table);
			goto fail;
		}
		dfa->tables[table->td_id] = table;
		blob += table_size(table->td_lolen, table->td_flags);
		size -= table_size(table->td_lolen, table->td_flags);
	}

	error = verify_dfa(dfa, flags);
	if (error)
		goto fail;

	return dfa;

fail:
	aa_dfa_free(dfa);
	return ERR_PTR(error);
}

void aa_dfa_free(struct aa_dfa *dfa)
{
	if (dfa) {
		int i;

		for (i = 0; i < ARRAY_SIZE(dfa->tables); i++) {
			free_table(dfa->tables[i]);
			dfa->tables[i] = NULL;
		}
	}
	kfree(dfa);
}

/**
 * aa_dfa_match_len - traverse @dfa to find state @str stops at
 * @dfa: the dfa to match @str against
 * @start: the state of the dfa to start matching in
 * @str: the string of bytes to match against the dfa
 * @len: length of the string of bytes to match
 *
 * aa_dfa_match_len will match @str against the dfa and return the state it
 * finished matching in. The final state can be used to look up the accepting
 * label, or as the start state of a continuing match.
 *
 * This function will happily match again the 0 byte and only finishes
 * when @len input is consumed.
 */
unsigned int aa_dfa_match_len(struct aa_dfa *dfa, unsigned int start,
			      const char *str, int len)
{
	u16 *def = DEFAULT_TABLE(dfa);
	u32 *base = BASE_TABLE(dfa);
	u16 *next = NEXT_TABLE(dfa);
	u16 *check = CHECK_TABLE(dfa);
	unsigned int state = start, pos;

	if (state == 0)
		return 0;

	/* current state is <state>, matching character *str */
	if (dfa->tables[YYTD_ID_EC]) {
		u8 *equiv = EQUIV_TABLE(dfa);
		for (; len; len--) {
			pos = base[state] + equiv[(u8) *str++];
			if (check[pos] == state)
				state = next[pos];
			else
				state = def[state];
		}
	} else {
		for (; len; len--) {
			pos = base[state] + (u8) *str++;
			if (check[pos] == state)
				state = next[pos];
			else
				state = def[state];
		}
	}
	return state;
}

/**
 * aa_dfa_next_state - traverse @dfa to find state @str stops at
 * @dfa: the dfa to match @str against
 * @start: the state of the dfa to start matching in
 * @str: the null terminated string of bytes to match against the dfa
 *
 * aa_dfa_next_state will match @str against the dfa and return the state it
 * finished matching in. The final state can be used to look up the accepting
 * label, or as the start state of a continuing match.
 */
unsigned int aa_dfa_match(struct aa_dfa *dfa, unsigned int start,
			  const char *str)
{
	return aa_dfa_match_len(dfa, start, str, strlen(str));
}
