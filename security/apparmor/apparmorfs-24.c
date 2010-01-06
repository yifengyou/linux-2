/*
 * AppArmor security module
 *
 * This file contains AppArmor /sys/kernel/secrutiy/apparmor interface functions
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2010 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 *
 * This file contain functions providing an interface for <= AppArmor 2.4
 * compatibility.  It is dependent on CONFIG_SECURITY_APPARMOR_COMPAT_24
 * being set (see Makefile).
 */

#include <linux/security.h>
#include <linux/vmalloc.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/namei.h>

#include "include/apparmor.h"
#include "include/audit.h"
#include "include/context.h"
#include "include/policy.h"


/* apparmor/matching */
static ssize_t aa_matching_read(struct file *file, char __user *buf,
				size_t size, loff_t *ppos)
{
	const char matching[] = "pattern=aadfa audit perms=crwxamlk/ "
	    "user::other";

	return simple_read_from_buffer(buf, size, ppos, matching,
				       sizeof(matching) - 1);
}

const struct file_operations aa_fs_matching_fops = {
	.read = aa_matching_read,
};

/* apparmor/features */
static ssize_t aa_features_read(struct file *file, char __user *buf,
				size_t size, loff_t *ppos)
{
	const char features[] = "file=3.1 capability=2.0 network=1.0 "
	    "change_hat=1.5 change_profile=1.1 " "aanamespaces=1.1 rlimit=1.1";

	return simple_read_from_buffer(buf, size, ppos, features,
				       sizeof(features) - 1);
}

const struct file_operations aa_fs_features_fops = {
	.read = aa_features_read,
};
