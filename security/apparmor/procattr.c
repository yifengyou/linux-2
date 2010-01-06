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
 * @profile: the profile to print profile info about
 * @string: the string that will contain the profile and namespace info
 *
 * Returns: length of @string on success else error on failure
 *
 * Requires: profile != NULL
 *
 * Creates a string containing the namespace_name://profile_name for
 * @profile.
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
	if (ns != default_namespace)
		ns_len = strlen(ns->base.name) + 3; /*+ 3 for :// */
	len = mode_len + ns_len + name_len + 1;	    /*+ 1 for \n */
	s = str = kmalloc(len + 1, GFP_ATOMIC);	    /* + 1 \0 */
	if (!str)
		return -ENOMEM;

	if (ns_len) {
		sprintf(s, "%s://", ns->base.name);
		s += ns_len;
	}
	sprintf(s, "%s (%s)\n",profile->base.hname, mode_str);
	*string = str;

	/* NOTE: len does not include \0 of string, not saved as part of file */
	return len;
}

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

int aa_setprocattr_changehat(char *args, int test)
{
	char *hat;
	u64 token;

	hat = split_token_from_name("change_hat", args, &token);
	if (IS_ERR(hat))
		return PTR_ERR(hat);

	if (!hat && !token) {
		AA_ERROR("change_hat: Invalid input, NULL hat and NULL magic");
		return -EINVAL;
	}

	AA_DEBUG("%s: Magic 0x%llx Hat '%s'\n",
		 __func__, token, hat ? hat : NULL);

	return aa_change_hat(hat, token, test);
}

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
