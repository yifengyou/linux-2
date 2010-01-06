/*
 * AppArmor security module
 *
 * This file contains basic common functions used in AppArmor
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2010 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include <linux/slab.h>
#include <linux/string.h>

#include "include/audit.h"


/**
 * aa_split_fqname - split a fqname into a profile and namespace name
 * @fqname: a full qualified name in namespace profile format
 * @ns_name: pointer to portion of the string containing the ns name
 *
 * Returns: profile name or NULL if one is not specified
 *
 * Split a namespace name from a profile name (see policy.c for naming
 * description).  If a portion of the name is missing it returns NULL for
 * that portion.
 *
 * NOTE: may modifiy the @fqname string.  The pointers returned point
 *       into the @fqname string.
 */
char *aa_split_fqname(char *fqname, char **ns_name)
{
	char *name = strstrip(fqname);

	*ns_name = NULL;
	if (fqname[0] == ':') {
		char *split = strchr(&fqname[1], ':');
		if (split) {
			/* overwrite ':' with \0 */
			*split = 0;
			name = strstrip(split + 1);
		} else
			/* a ns name without a following profile is allowed */
			name = NULL;
		*ns_name = &fqname[1];
	}
	if (name && *name == 0)
		name = NULL;

	return name;
}

/**
 * aa_strneq - compare null terminated @str to a non null terminated substring
 * @str: a null terminated string
 * @sub: a substring, not necessarily null terminated
 * @len: length of @sub to compare
 *
 * The @str string must be full consumed for this to be considered a match
 */
bool aa_strneq(const char *str, const char *sub, int len)
{
	int res = strncmp(str, sub, len);
	if (res)
		return 0;
	if (str[len] == 0)
		return 1;
	return 0;
}

void aa_info_message(const char *str)
{
	struct aa_audit sa = {
		.gfp_mask = GFP_KERNEL,
		.info = str,
	};
	printk(KERN_INFO "AppArmor: %s\n", str);
	if (audit_enabled)
		aa_audit(AUDIT_APPARMOR_STATUS, NULL, &sa, NULL);
}

