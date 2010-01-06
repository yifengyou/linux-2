/*
 * AppArmor security module
 *
 * This file contains AppArmor functions for unpacking policy loaded from
 * userspace.
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2010 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * AppArmor uses a serialized binary format for loading policy.
 * The policy format is documented in Documentation/???
 * All policy is validated all before it is used.
 */

#include <asm/unaligned.h>
#include <linux/errno.h>

#include "include/apparmor.h"
#include "include/audit.h"
#include "include/context.h"
#include "include/match.h"
#include "include/policy.h"
#include "include/policy_unpack.h"
#include "include/sid.h"

/*
 * The AppArmor interface treats data as a type byte followed by the
 * actual data.  The interface has the notion of a a named entry
 * which has a name (AA_NAME typecode followed by name string) followed by
 * the entries typecode and data.  Named types allow for optional
 * elements and extensions to be added and tested for without breaking
 * backwards compatability.
 */

enum aa_code {
	AA_U8,
	AA_U16,
	AA_U32,
	AA_U64,
	AA_NAME,		/* same as string except it is items name */
	AA_STRING,
	AA_BLOB,
	AA_STRUCT,
	AA_STRUCTEND,
	AA_LIST,
	AA_LISTEND,
	AA_ARRAY,
	AA_ARRAYEND,
};

/*
 * aa_ext is the read of the buffer containing the serialized profile.  The
 * data is copied into a kernel buffer in apparmorfs and then handed off to
 * the unpack routines.
 */
struct aa_ext {
	void *start;
	void *end;
	void *pos;		/* pointer to current position in the buffer */
	u32 version;
};

static void audit_cb(struct audit_buffer *ab, struct aa_audit *va)
{
	struct aa_audit_iface *sa = container_of(va, struct aa_audit_iface,
						 base);

	if (sa->name) {
		audit_log_format(ab, " name=");
		audit_log_string(ab, sa->name);
	}
	if (sa->name2) {
		audit_log_format(ab, " namespace=");
		audit_log_string(ab, sa->name2);
	}
	if (sa->base.error && sa->pos)
		audit_log_format(ab, " offset=%ld", sa->pos);
}

int aa_audit_iface(struct aa_audit_iface *sa)
{
	struct aa_profile *profile;
	struct cred *cred = aa_get_task_cred(current, &profile);
	int error = aa_audit(AUDIT_APPARMOR_STATUS, profile, &sa->base,
			     audit_cb);
	put_cred(cred);
	return error;
}

static bool aa_inbounds(struct aa_ext *e, size_t size)
{
	return (size <= e->end - e->pos);
}

/**
 * aa_u16_chunck - test and do bounds checking for a u16 size based chunk
 * @e: serialized data read head
 * @chunk: start address for chunk of data
 *
 * return the size of chunk found with the read head at the end of
 * the chunk.
 */
static size_t unpack_u16_chunk(struct aa_ext *e, char **chunk)
{
	size_t size = 0;

	if (!aa_inbounds(e, sizeof(u16)))
		return 0;
	size = le16_to_cpu(get_unaligned((u16 *) e->pos));
	e->pos += sizeof(u16);
	if (!aa_inbounds(e, size))
		return 0;
	*chunk = e->pos;
	e->pos += size;
	return size;
}

static bool unpack_X(struct aa_ext *e, enum aa_code code)
{
	if (!aa_inbounds(e, 1))
		return 0;
	if (*(u8 *) e->pos != code)
		return 0;
	e->pos++;
	return 1;
}

/**
 * unpack_nameX - check is the next element is of type X with a name of @name
 * @e: serialized data extent information
 * @code: type code
 * @name: name to match to the serialized element.
 *
 * check that the next serialized data element is of type X and has a tag
 * name @name.  If @name is specified then there must be a matching
 * name element in the stream.  If @name is NULL any name element will be
 * skipped and only the typecode will be tested.
 * returns 1 on success (both type code and name tests match) and the read
 * head is advanced past the headers
 *
 * Returns: 0 if either match failes, the read head does not move
 */
static bool unpack_nameX(struct aa_ext *e, enum aa_code code, const char *name)
{
	/*
	 * May need to reset pos if name or type doesn't match
	 */
	void *pos = e->pos;
	/*
	 * Check for presence of a tagname, and if present name size
	 * AA_NAME tag value is a u16.
	 */
	if (unpack_X(e, AA_NAME)) {
		char *tag = NULL;
		size_t size = unpack_u16_chunk(e, &tag);
		/* if a name is specified it must match. otherwise skip tag */
		if (name && (!size || strcmp(name, tag)))
			goto fail;
	} else if (name) {
		/* if a name is specified and there is no name tag fail */
		goto fail;
	}

	/* now check if type code matches */
	if (unpack_X(e, code))
		return 1;

fail:
	e->pos = pos;
	return 0;
}

static bool unpack_u16(struct aa_ext *e, u16 *data, const char *name)
{
	if (unpack_nameX(e, AA_U16, name)) {
		if (!aa_inbounds(e, sizeof(u16)))
			return 0;
		if (data)
			*data = le16_to_cpu(get_unaligned((u16 *) e->pos));
		e->pos += sizeof(u16);
		return 1;
	}
	return 0;
}

static bool unpack_u32(struct aa_ext *e, u32 *data, const char *name)
{
	if (unpack_nameX(e, AA_U32, name)) {
		if (!aa_inbounds(e, sizeof(u32)))
			return 0;
		if (data)
			*data = le32_to_cpu(get_unaligned((u32 *) e->pos));
		e->pos += sizeof(u32);
		return 1;
	}
	return 0;
}

static bool unpack_u64(struct aa_ext *e, u64 *data, const char *name)
{
	if (unpack_nameX(e, AA_U64, name)) {
		if (!aa_inbounds(e, sizeof(u64)))
			return 0;
		if (data)
			*data = le64_to_cpu(get_unaligned((u64 *) e->pos));
		e->pos += sizeof(u64);
		return 1;
	}
	return 0;
}

static size_t unpack_array(struct aa_ext *e, const char *name)
{
	if (unpack_nameX(e, AA_ARRAY, name)) {
		int size;
		if (!aa_inbounds(e, sizeof(u16)))
			return 0;
		size = (int)le16_to_cpu(get_unaligned((u16 *) e->pos));
		e->pos += sizeof(u16);
		return size;
	}
	return 0;
}

static size_t unpack_blob(struct aa_ext *e, char **blob, const char *name)
{
	if (unpack_nameX(e, AA_BLOB, name)) {
		u32 size;
		if (!aa_inbounds(e, sizeof(u32)))
			return 0;
		size = le32_to_cpu(get_unaligned((u32 *) e->pos));
		e->pos += sizeof(u32);
		if (aa_inbounds(e, (size_t) size)) {
			*blob = e->pos;
			e->pos += size;
			return size;
		}
	}
	return 0;
}

static int unpack_str(struct aa_ext *e, const char **string, const char *name)
{
	char *src_str;
	size_t size = 0;
	void *pos = e->pos;
	*string = NULL;
	if (unpack_nameX(e, AA_STRING, name)) {
		size = unpack_u16_chunk(e, &src_str);
		if (size) {
			/* strings are null terminated, length is size - 1 */
			if (src_str[size - 1] != 0)
				goto fail;
			*string = src_str;
		}
	}
	return size;

fail:
	e->pos = pos;
	return 0;
}

static int unpack_strdup(struct aa_ext *e, char **string, const char *name)
{
	const char *tmp;
	void *pos = e->pos;
	int res = unpack_str(e, &tmp, name);
	*string = NULL;

	if (!res)
		return 0;

	*string = kmemdup(tmp, res, GFP_KERNEL);
	if (!*string) {
		e->pos = pos;
		return 0;
	}

	return res;
}

static bool verify_accept(struct aa_dfa *dfa, int flags)
{
	int i;

	/* verify accept permissions */
	for (i = 0; i < dfa->tables[YYTD_ID_ACCEPT]->td_lolen; i++) {
		int mode = ACCEPT_TABLE(dfa)[i];

		if (mode & ~DFA_VALID_PERM_MASK)
			return 0;

		if (ACCEPT_TABLE2(dfa)[i] & ~DFA_VALID_PERM2_MASK)
			return 0;
	}
	return 1;
}

/**
 * unpack_dfa - unpack a file rule dfa
 * @e: serialized data extent information
 *
 * returns dfa or ERR_PTR
 */
static struct aa_dfa *unpack_dfa(struct aa_ext *e)
{
	char *blob = NULL;
	size_t size;
	struct aa_dfa *dfa = NULL;

	size = unpack_blob(e, &blob, "aadfa");
	if (size) {
		/*
		 * The dfa is aligned with in the blob to 8 bytes
		 * from the beginning of the stream.
		 */
		size_t sz = blob - (char *)e->start;
		size_t pad = ALIGN(sz, 8) - sz;
		int flags = TO_ACCEPT1_FLAG(YYTD_DATA32) |
			TO_ACCEPT2_FLAG(YYTD_DATA32);


		if (aa_g_paranoid_load)
			flags |= DFA_FLAG_VERIFY_STATES;

		dfa = aa_dfa_unpack(blob + pad, size - pad, flags);

		if (aa_g_paranoid_load && !verify_accept(dfa, flags))
			goto fail;
	}

	return dfa;

fail:
	aa_dfa_free(dfa);
	return ERR_PTR(-EPROTO);
}

static bool unpack_trans_table(struct aa_ext *e, struct aa_profile *profile)
{
	void *pos = e->pos;

	/* exec table is optional */
	if (unpack_nameX(e, AA_STRUCT, "xtable")) {
		int i, size;

		size = unpack_array(e, NULL);
		/* currently 4 exec bits and entries 0-3 are reserved iupcx */
		if (size > 16 - 4)
			goto fail;
		profile->file.trans.table = kzalloc(sizeof(char *) * size,
						    GFP_KERNEL);
		if (!profile->file.trans.table)
			goto fail;

		profile->file.trans.size = size;
		for (i = 0; i < size; i++) {
			char *str;
			int c, j, size = unpack_strdup(e, &str, NULL);
			if (!size)
				goto fail;
			/*
			 * verify: transition names string
			 */
			for (c = j = 0; j < size - 1; j++) {
				if (!str[j])
					c++;
			}
			/* names beginning with : require an embedded \0 */
			if (*str == ':' && c != 1)
				goto fail;
			/* fail - all other cases with embedded \0 */
			else if (c)
				goto fail;
			profile->file.trans.table[i] = str;
		}
		if (!unpack_nameX(e, AA_ARRAYEND, NULL))
			goto fail;
		if (!unpack_nameX(e, AA_STRUCTEND, NULL))
			goto fail;
	}
	return 1;

fail:
	aa_free_domain_entries(&profile->file.trans);
	e->pos = pos;
	return 0;
}

static bool unpack_rlimits(struct aa_ext *e, struct aa_profile *profile)
{
	void *pos = e->pos;

	/* rlimits are optional */
	if (unpack_nameX(e, AA_STRUCT, "rlimits")) {
		int i, size;
		u32 tmp = 0;
		if (!unpack_u32(e, &tmp, NULL))
			goto fail;
		profile->rlimits.mask = tmp;

		size = unpack_array(e, NULL);
		if (size > RLIM_NLIMITS)
			goto fail;
		for (i = 0; i < size; i++) {
			u64 tmp = 0;
			if (!unpack_u64(e, &tmp, NULL))
				goto fail;
			profile->rlimits.limits[i].rlim_max = tmp;
		}
		if (!unpack_nameX(e, AA_ARRAYEND, NULL))
			goto fail;
		if (!unpack_nameX(e, AA_STRUCTEND, NULL))
			goto fail;
	}
	return 1;

fail:
	e->pos = pos;
	return 0;
}

/**
 * unpack_profile - unpack a serialized profile
 * @e: serialized data extent information
 * @sa: audit struct for the operation
 *
 * NOTE: unpack profile sets audit struct if there is a failure
 */
static struct aa_profile *unpack_profile(struct aa_ext *e,
					    struct aa_audit_iface *sa)
{
	struct aa_profile *profile = NULL;
	const char *name = NULL;
	size_t size = 0;
	int i, error = -EPROTO;
	u32 tmp;
	u64 tmp64;

	/* check that we have the right struct being passed */
	if (!unpack_nameX(e, AA_STRUCT, "profile"))
		goto fail;
	if (!unpack_str(e, &name, NULL))
		goto fail;

	profile = aa_alloc_profile(name);
	if (!profile)
		return ERR_PTR(-ENOMEM);

	/* profile renaming is optional */
	(void) unpack_str(e, &profile->rename, "rename");

	/* xmatch is optional and may be NULL */
	profile->xmatch = unpack_dfa(e);
	if (IS_ERR(profile->xmatch)) {
		error = PTR_ERR(profile->xmatch);
		profile->xmatch = NULL;
		goto fail;
	}
	/* xmatch_len is not optional is xmatch is set */
	if (profile->xmatch && !unpack_u32(e, &tmp, NULL))
		goto fail;
	profile->xmatch_len = tmp;

	/* per profile debug flags (complain, audit) */
	if (!unpack_nameX(e, AA_STRUCT, "flags"))
		goto fail;
	if (!unpack_u32(e, &tmp, NULL))
		goto fail;
	if (tmp)
		profile->flags |= PFLAG_HAT;
	if (!unpack_u32(e, &tmp, NULL))
		goto fail;
	if (tmp)
		profile->mode = APPARMOR_COMPLAIN;
	if (!unpack_u32(e, &tmp, NULL))
		goto fail;
	if (tmp)
		profile->audit = AUDIT_ALL;

	if (!unpack_nameX(e, AA_STRUCTEND, NULL))
		goto fail;

	/* mmap_min_addr is optional */
	if (unpack_u64(e, &tmp64, "mmap_min_addr")) {
		profile->mmap_min_addr = (unsigned long)tmp64;
		if (((u64) profile->mmap_min_addr) == tmp64) {
			profile->flags |= PFLAG_MMAP_MIN_ADDR;
		} else {
			sa->base.info = "invalid set mmap_min_addr";
			goto fail;
		}
	}

	if (!unpack_u32(e, &(profile->caps.allowed.cap[0]), NULL))
		goto fail;
	if (!unpack_u32(e, &(profile->caps.audit.cap[0]), NULL))
		goto fail;
	if (!unpack_u32(e, &(profile->caps.quiet.cap[0]), NULL))
		goto fail;
	if (!unpack_u32(e, &(profile->caps.set.cap[0]), NULL))
		goto fail;

	if (unpack_nameX(e, AA_STRUCT, "caps64")) {
		/* optional upper half of 64 bit caps */
		if (!unpack_u32(e, &(profile->caps.allowed.cap[1]), NULL))
			goto fail;
		if (!unpack_u32(e, &(profile->caps.audit.cap[1]), NULL))
			goto fail;
		if (!unpack_u32(e, &(profile->caps.quiet.cap[1]), NULL))
			goto fail;
		if (!unpack_u32(e, &(profile->caps.set.cap[1]), NULL))
			goto fail;
		if (!unpack_nameX(e, AA_STRUCTEND, NULL))
			goto fail;
	}

	if (!unpack_rlimits(e, profile))
		goto fail;

	size = unpack_array(e, "net_allowed_af");
	if (size) {
		if (size > AF_MAX)
			goto fail;

		for (i = 0; i < size; i++) {
			if (!unpack_u16(e, &profile->net.allowed[i], NULL))
				goto fail;
			if (!unpack_u16(e, &profile->net.audit[i], NULL))
				goto fail;
			if (!unpack_u16(e, &profile->net.quiet[i], NULL))
				goto fail;
		}
		if (!unpack_nameX(e, AA_ARRAYEND, NULL))
			goto fail;
		/*
		 * allow unix domain and netlink sockets they are handled
		 * by IPC
		 */
	}
	profile->net.allowed[AF_UNIX] = 0xffff;
	profile->net.allowed[AF_NETLINK] = 0xffff;

	/* get file rules */
	profile->file.dfa = unpack_dfa(e);
	if (IS_ERR(profile->file.dfa)) {
		error = PTR_ERR(profile->file.dfa);
		profile->file.dfa = NULL;
		goto fail;
	}

	if (!unpack_trans_table(e, profile))
		goto fail;

	if (!unpack_nameX(e, AA_STRUCTEND, NULL))
		goto fail;

	return profile;

fail:
	sa->name = name ? name : "unknown";
	if (!sa->base.info)
		sa->base.info = "failed to unpack profile";

	aa_put_profile(profile);

	return ERR_PTR(error);
}

/**
 * aa_verify_head - unpack serialized stream header
 * @e: serialized data read head
 * @operation: operation header is being verified for
 *
 * Returns: error or 0 if header is good
 */
static int aa_verify_header(struct aa_ext *e, struct aa_audit_iface *sa)
{
	/* get the interface version */
	if (!unpack_u32(e, &e->version, "version")) {
		sa->base.info = "invalid profile format";
		aa_audit_iface(sa);
		return -EPROTONOSUPPORT;
	}

	/* check that the interface version is currently supported */
	if (e->version != 5) {
		sa->base.info = "unsupported interface version";
		aa_audit_iface(sa);
		return -EPROTONOSUPPORT;
	}

	/* read the namespace if present */
	if (!unpack_str(e, &sa->name2, "namespace"))
		sa->name2 = NULL;

	return 0;
}

/**
 * verify_profile - Do post unpack analysis to verify profile consistency
 * @profile: profile to verify
 *
 * Returns: 0 if passes verification else error
 */
static bool verify_xindex(int xindex, int table_size)
{
	int index, xtype;
	xtype = xindex & AA_X_TYPE_MASK;
	index = xindex & AA_X_INDEX_MASK;
	if (xtype == AA_X_TABLE && index > table_size)
		return 0;
	return 1;
}

/* verify dfa xindexes are in range of transition tables */
static bool verify_dfa_xindex(struct aa_dfa *dfa, int table_size)
{
	int i;
	for (i = 0; i < dfa->tables[YYTD_ID_ACCEPT]->td_lolen; i++) {
		if (!verify_xindex(dfa_user_xindex(dfa, i), table_size))
			return 0;
		if (!verify_xindex(dfa_other_xindex(dfa, i), table_size))
			return 0;
	}
	return 1;
}

static int verify_profile(struct aa_profile *profile, struct aa_audit_iface *sa)
{
	if (aa_g_paranoid_load) {
		if (!verify_dfa_xindex(profile->file.dfa,
				       profile->file.trans.size)) {
			sa->base.info = "Invalid named transition";
			return -EPROTO;
		}
	}

	return 0;
}

/**
 * aa_unpack - unpack packed binary profile data loaded from user space
 * @udata: user data copied to kmem
 * @size: the size of the user data
 * @sa: audit struct for unpacking
 *
 * Unpack user data and return refcounted allocated profile or ERR_PTR
 */
struct aa_profile *aa_unpack(void *udata, size_t size,
			     struct aa_audit_iface *sa)
{
	struct aa_profile *profile;
	int error;
	struct aa_ext e = {
		.start = udata,
		.end = udata + size,
		.pos = udata,
	};

	error = aa_verify_header(&e, sa);
	if (error)
		return ERR_PTR(error);

	profile = unpack_profile(&e, sa);
	if (IS_ERR(profile))
		sa->pos = e.pos - e.start;

	error = verify_profile(profile, sa);
	if (error) {
		aa_put_profile(profile);
		profile = ERR_PTR(error);
	}

	/* return refcount */
	return profile;
}
