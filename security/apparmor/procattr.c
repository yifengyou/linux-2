/*
 * AppArmor security module
 *
 * This file contains AppArmor /proc/<pid>/attr/ interface functions
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2010 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include "include/apparmor.h"
#include "include/policy.h"
#include "include/domain.h"

/**
 * aa_getprocattr - Return the profile information for @profile
 * @profile: the profile to print profile info about  (NOT NULL)
 * @string: the string that will contain the profile and namespace info (!NULL)
 *
 * Returns: length of @string on success else error on failure
 *
 * Requires: profile != NULL
 *
 * Creates a string containing the namespace_name://profile_name for
 * @profile.
 *
 * Returns: size of string placed in @string else error code on failure
 */
int aa_getprocattr(struct aa_profile *profile, char **string)
{
	char *str;
	int len = 0, mode_len, name_len, ns_len = 0;
	const char *mode_str = profile_mode_names[profile->mode];
	struct aa_namespace *ns = profile->ns;
	char *s;

	mode_len = strlen(mode_str) + 3;	/* + 3 for _() */
	name_len = strlen(profile->base.hname);
	if (ns != root_ns)
		ns_len = strlen(ns->base.name) + 3; /*+ 3 for :// */
	len = mode_len + ns_len + name_len + 1;	    /*+ 1 for \n */
	s = str = kmalloc(len + 1, GFP_ATOMIC);	    /* + 1 \0 */
	if (!str)
		return -ENOMEM;

	if (ns_len) {
		sprintf(s, "%s://", ns->base.name);
		s += ns_len;
	}
	if (profile->flags & PFLAG_UNCONFINED)
		sprintf(s, "%s\n", profile->base.hname);
	else
		sprintf(s, "%s (%s)\n", profile->base.hname, mode_str);
	*string = str;

	/* NOTE: len does not include \0 of string, not saved as part of file */
	return len;
}

/**
 * split_token_from_name - separate a string of form  <token>^<name>
 * @op: operation name  (NOT NULL)
 * @args: string to parse  (NOT NULL)
 * @token: stores returned parsed token value  (NOT NULL)
 *
 * Returns: start position of name after token else NULL on failure
 */
static char *split_token_from_name(const char *op, char *args, u64 * token)
{
	char *name;

	*token = simple_strtoull(args, &name, 16);
	if ((name == args) || *name != '^') {
		AA_ERROR("%s: Invalid input '%s'", op, args);
		return ERR_PTR(-EINVAL);
	}

	name++;			/* skip ^ */
	if (!*name)
		name = NULL;
	return name;
}

/**
 * aa_setprocattr_chagnehat - handle procattr interface to change_hat
 * @args: args received from writing to /proc/<pid>/attr/current (NOT NULL)
 * @size: size of the args
 * @test: true if this is a test of change_hat permissions
 *
 * Returns: %0 or error code if change_hat fails
 */
int aa_setprocattr_changehat(char *args, size_t size, int test)
{
	char *hat;
	u64 token;
	const char *hats[16];		/* current hard limit on # of names */
	int count = 0;

	hat = split_token_from_name("change_hat", args, &token);
	if (IS_ERR(hat))
		return PTR_ERR(hat);

	if (!hat && !token) {
		AA_ERROR("change_hat: Invalid input, NULL hat and NULL magic");
		return -EINVAL;
	}

	if (hat) {
		/* set up hat name vector, args guarenteed null terminated
		 * at args[size]
		 */
		char *end = args + size;
		for (count = 0; (hat < end) && count < 16; ++count) {
			char *next = hat + strlen(hat) + 1;
			hats[count] = hat;
			hat = next;
		}
	}

	AA_DEBUG("%s: Magic 0x%llx Hat '%s'\n",
		 __func__, token, hat ? hat : NULL);

	return aa_change_hat(hats, count, token, test);
}

/**
 * aa_setprocattr_changeprofile - handle procattr interface to changeprofile
 * @fqname: args received from writting to /proc/<pid>/attr/current (NOT NULL)
 * @onexec: true if change_profile should be delayed until exec
 * @test: true if this is a test of change_profile permissions
 *
 * Returns: %0 or error code if change_profile fails
 */
int aa_setprocattr_changeprofile(char *fqname, int onexec, int test)
{
	char *name, *ns_name;

	name = aa_split_fqname(fqname, &ns_name);
	return aa_change_profile(ns_name, name, onexec, test);
}

int aa_setprocattr_permipc(char *fqname)
{
	/* TODO: add ipc permission querying */
	return -ENOTSUPP;
}
