/*
 * AppArmor security module
 *
 * This file contains AppArmor /sys/kernel/secrutiy/apparmor interface functions
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009 Canonical Ltd.
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

/**
 * next_profile - step to the next profile to be output
 * @profile: profile that was last output
 *
 * Perform a depth first traversal over profile tree.
 *
 * Returns: next profile or NULL if done
 * Requires: ns_list_lock, and profile->ns->base.lock be held
 *           will unlock profile->ns.base.lock and aquire lock for next ns
 *           __releases(last ns lock);
 */
static struct aa_profile *next_profile(struct aa_profile *profile)
{
	struct aa_profile *parent;
	struct aa_namespace *ns = profile->ns;

	/* is next profile a child */
	if (!list_empty(&profile->base.profiles))
		return list_first_entry(&profile->base.profiles,
					struct aa_profile, base.list);

	/* is next a sibling, parent sibling, gp sibling */
	parent = profile->parent;
	while (parent) {
		list_for_each_entry_continue(profile, &parent->base.profiles,
					     base.list)
			return profile;
		profile = parent;
		parent = parent->parent;
	}

	/* is next the another profile in the namespace */
	list_for_each_entry_continue(profile, &ns->base.profiles, base.list)
		return profile;

	/* finished all profiles in namespace move to next namespace */
	read_unlock(&ns->base.lock);
	list_for_each_entry_continue(ns, &ns_list, base.list) {
		read_lock(&ns->base.lock);
		return list_first_entry(&ns->base.profiles, struct aa_profile,
					base.list);
	}

	/* done all profiles */
	return NULL;
}

/**
 * p_start - start a depth first traversal of profile tree
 * @f: seq_file to fill
 * @pos: current position
 *
 * acquires first ns->base.lock
 */
static void *p_start(struct seq_file *f, loff_t *pos) __acquires(ns_list_lock)
{
	struct aa_namespace *ns;
	loff_t l = *pos;

	read_lock(&ns_list_lock);
	if (!list_empty(&ns_list)) {
		struct aa_profile *profile = NULL;
		ns = list_first_entry(&ns_list, typeof(*ns), base.list);
		read_lock(&ns->base.lock);
		if (!list_empty(&ns->base.profiles)) {
			profile = list_first_entry(&ns->base.profiles,
						   typeof(*profile), base.list);
			/* skip to position */
			for (; profile && l > 0; l--)
				profile = next_profile(profile);
			return profile;
		} else
			read_unlock(&ns->base.lock);
	}
	return NULL;
}

static void *p_next(struct seq_file *f, void *p, loff_t *pos)
{
	struct aa_profile *profile = (struct aa_profile *)p;

	(*pos)++;
	profile = next_profile(profile);

	return profile;
}

/**
 * p_stop - stop depth first traversal
 * @f: seq_file we are filling
 * @p: the last profile writen
 *
 * if we haven't completely traversed the profile tree will release the
 * ns->base.lock, if we have the ns->base.lock was released in next_profile
 */
static void p_stop(struct seq_file *f, void *p) __releases(ns_list_lock)
{
	struct aa_profile *profile = (struct aa_profile *)p;

	if (profile)
		read_unlock(&profile->ns->base.lock);
	read_unlock(&ns_list_lock);
}

static void print_name(struct seq_file *f, struct aa_profile *profile)
{
	if (profile->parent) {
		print_name(f, profile->parent);
		seq_printf(f, "//");
	}
	seq_printf(f, "%s", profile->base.name);
}

/* Returns: error on failure */
static int seq_show_profile(struct seq_file *f, void *p)
{
	struct aa_profile *profile = (struct aa_profile *)p;

	if (profile->ns != default_namespace)
		seq_printf(f, ":%s:", profile->ns->base.name);
	print_name(f, profile);
	seq_printf(f, " (%s)\n",
		   PROFILE_COMPLAIN(profile) ? "complain" : "enforce");

	return 0;
}

/* Used in apparmorfs.c */
static const struct seq_operations aa_fs_profiles_op = {
	.start = p_start,
	.next = p_next,
	.stop = p_stop,
	.show = seq_show_profile,
};

static int aa_profiles_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &aa_fs_profiles_op);
}

static int aa_profiles_release(struct inode *inode, struct file *file)
{
	return seq_release(inode, file);
}

const struct file_operations aa_fs_profiles_fops = {
	.open = aa_profiles_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = aa_profiles_release,
};

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
