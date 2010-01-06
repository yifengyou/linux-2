/*
 * AppArmor security module
 *
 * This file contains AppArmor /sys/kernel/security/apparmor interface functions
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2010 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include <linux/security.h>
#include <linux/vmalloc.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/namei.h>

#include "include/apparmor.h"
#include "include/apparmorfs.h"
#include "include/audit.h"
#include "include/context.h"
#include "include/policy.h"

static void *kvmalloc(size_t size)
{
	void *buffer = kmalloc(size, GFP_KERNEL);
	if (!buffer)
		buffer = vmalloc(size);
	return buffer;
}

static void kvfree(void *buffer)
{
	if (is_vmalloc_addr(buffer))
		vfree(buffer);
	else
		kfree(buffer);
}

static char *aa_simple_write_to_buffer(const char __user *userbuf,
				       size_t alloc_size, size_t copy_size,
				       loff_t *pos, const char *operation)
{
	char *data;

	if (*pos != 0) {
		/* only writes from pos 0, that is complete writes */
		data = ERR_PTR(-ESPIPE);
		goto out;
	}

	/*
	 * Don't allow profile load/replace/remove from profiles that don't
	 * have CAP_MAC_ADMIN
	 */
	if (!capable(CAP_MAC_ADMIN)) {
		struct aa_profile *profile = NULL;
		struct aa_audit sa = {
			.operation = operation,
			.gfp_mask = GFP_KERNEL,
			.error = -EACCES,
		};
		profile = aa_current_profile();
		data = ERR_PTR(aa_audit(AUDIT_APPARMOR_DENIED, profile, &sa,
					NULL));
		goto out;
	}
	/* freed by caller to aa_simple_write_to_buffer */
	data = kvmalloc(alloc_size);
	if (data == NULL) {
		data = ERR_PTR(-ENOMEM);
		goto out;
	}

	if (copy_from_user(data, userbuf, copy_size)) {
		kvfree(data);
		data = ERR_PTR(-EFAULT);
		goto out;
	}

out:
	return data;
}

/* apparmor/.load */
static ssize_t aa_profile_load(struct file *f, const char __user *buf,
			       size_t size, loff_t *pos)
{
	char *data;
	ssize_t error;

	data = aa_simple_write_to_buffer(buf, size, size, pos, "profile_load");

	error = PTR_ERR(data);
	if (!IS_ERR(data)) {
		error = aa_interface_replace_profiles(data, size, 1);
		kvfree(data);
	}

	return error;
}

static const struct file_operations aa_fs_profile_load = {
	.write = aa_profile_load
};

/* apparmor/.replace */
static ssize_t aa_profile_replace(struct file *f, const char __user *buf,
				  size_t size, loff_t *pos)
{
	char *data;
	ssize_t error;

	data = aa_simple_write_to_buffer(buf, size, size, pos,
					 "profile_replace");
	error = PTR_ERR(data);
	if (!IS_ERR(data)) {
		error = aa_interface_replace_profiles(data, size, 0);
		kvfree(data);
	}

	return error;
}

static const struct file_operations aa_fs_profile_replace = {
	.write = aa_profile_replace
};

/* apparmor/.remove */
static ssize_t aa_profile_remove(struct file *f, const char __user *buf,
				 size_t size, loff_t *pos)
{
	char *data;
	ssize_t error;

	/*
	 * aa_remove_profile needs a null terminated string so 1 extra
	 * byte is allocated and the copied data is null terminated.
	 */
	data = aa_simple_write_to_buffer(buf, size + 1, size, pos,
					 "profile_remove");

	error = PTR_ERR(data);
	if (!IS_ERR(data)) {
		data[size] = 0;
		error = aa_interface_remove_profiles(data, size);
		kvfree(data);
	}

	return error;
}

static const struct file_operations aa_fs_profile_remove = {
	.write = aa_profile_remove
};

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

static const struct file_operations aa_fs_profiles_fops = {
	.open = aa_profiles_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = aa_profiles_release,
};


/** Base file system setup **/

static struct dentry *aa_fs_dentry;
struct dentry *aa_fs_null;
struct vfsmount *aa_fs_mnt;

static void aafs_remove(const char *name)
{
	struct dentry *dentry;

	dentry = lookup_one_len(name, aa_fs_dentry, strlen(name));
	if (!IS_ERR(dentry)) {
		securityfs_remove(dentry);
		dput(dentry);
	}
}

/**
 * aafs_create - create an entry in the apparmor filesystem
 * @name: name of the entry
 * @mask: file permission mask of the file
 * @fops: file operations for the file
 *
 * Used aafs_remove to remove entries created with this fn.
 */
static int aafs_create(const char *name, int mask,
		       const struct file_operations *fops)
{
	struct dentry *dentry;

	dentry = securityfs_create_file(name, S_IFREG | mask, aa_fs_dentry,
					NULL, fops);

	return IS_ERR(dentry) ? PTR_ERR(dentry) : 0;
}

/**
 * aa_destroy_aafs - cleanup and free aafs
 *
 * releases dentries allocated by aa_create_aafs
 */
void aa_destroy_aafs(void)
{
	if (aa_fs_dentry) {
		aafs_remove(".remove");
		aafs_remove(".replace");
		aafs_remove(".load");
		aafs_remove("profiles");
#ifdef CONFIG_SECURITY_APPARMOR_COMPAT_24
		aafs_remove("matching");
		aafs_remove("features");
#endif
		securityfs_remove(aa_fs_dentry);
		aa_fs_dentry = NULL;
	}
}

/**
 * aa_create_aafs - create the apparmor security filesystem
 *
 * dentries created here are released by aa_destroy_aafs
 *
 * Returns: error on failure
 */
int aa_create_aafs(void)
{
	int error;

	if (!apparmor_initialized)
		return 0;

	if (aa_fs_dentry) {
		AA_ERROR("%s: AppArmor securityfs already exists\n", __func__);
		return -EEXIST;
	}

	aa_fs_dentry = securityfs_create_dir("apparmor", NULL);
	if (IS_ERR(aa_fs_dentry)) {
		error = PTR_ERR(aa_fs_dentry);
		aa_fs_dentry = NULL;
		goto error;
	}
#ifdef CONFIG_SECURITY_APPARMOR_COMPAT_24
	error = aafs_create("matching", 0444, &aa_fs_matching_fops);
	if (error)
		goto error;
	error = aafs_create("features", 0444, &aa_fs_features_fops);
	if (error)
		goto error;
#endif
	error = aafs_create("profiles", 0440, &aa_fs_profiles_fops);
	if (error)
		goto error;
	error = aafs_create(".load", 0640, &aa_fs_profile_load);
	if (error)
		goto error;
	error = aafs_create(".replace", 0640, &aa_fs_profile_replace);
	if (error)
		goto error;
	error = aafs_create(".remove", 0640, &aa_fs_profile_remove);
	if (error)
		goto error;

	/* TODO: add support for apparmorfs_null and apparmorfs_mnt */

	/* Report that AppArmor fs is enabled */
	aa_info_message("AppArmor Filesystem Enabled");
	return 0;

error:
	aa_destroy_aafs();
	AA_ERROR("Error creating AppArmor securityfs\n");
	apparmor_disable();
	return error;
}

fs_initcall(aa_create_aafs);
