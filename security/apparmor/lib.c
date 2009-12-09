/*
 * AppArmor security module
 *
 * This file contains basic common functions used in AppArmor
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include <linux/slab.h>
#include <linux/string.h>

#include "include/audit.h"


char *aa_split_name_from_ns(char *args, char **ns_name)
{
	char *name = strstrip(args);

	*ns_name = NULL;
	if (args[0] == ':') {
		char *split = strstrip(strchr(&args[1], ':'));

		if (!split)
			return NULL;

		*split = 0;
		*ns_name = &args[1];
		name = strstrip(split + 1);
	}
	if (*name == 0)
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

