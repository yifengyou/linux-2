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

/**
 * kvmalloc - do allocation prefering kmalloc but falling back to vmalloc
 * @size: size of allocation
 *
 * Return: allocated buffer or NULL if failed
 *
 * It is possible that policy being loaded from the user is larger than
 * what can be allocated by kmalloc, in those cases fall back to vmalloc.
 */
static void *kvmalloc(size_t size)
{
	void *buffer;

	if (size == 0)
		return NULL;

	buffer = kmalloc(size, GFP_KERNEL);
	if (!buffer)
		buffer = vmalloc(size);
	return buffer;
}

/**
 * kvfree - free an allocation do by kvmalloc
 * @buffer: buffer to free
 *
 * Free a buffer allocated by kvmalloc
 */
static void kvfree(void *buffer)
{
	if (!buffer)
		return;

	if (is_vmalloc_addr(buffer))
		vfree(buffer);
	else
		kfree(buffer);
}

/**
 * aa_simple_write_to_buffer - common routine for getting policy from user
 * @userbuf: user buffer to copy data from  (NOT NULL)
 * @alloc_size: size of user buffer
 * @copy_size: size of data to copy from user buffer
 * @pos: position write is at in the file
 * @operation: name of operation doing the user buffer copy (NOT NULL)
 *
 * Returns: kernel buffer containing copy of user buffer data or an
 *          ERR_PTR on failure.
 */
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


/* .load file hook fn to load policy */
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

/* .replace file hook fn to load and/or replace policy */
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

/* .remove file hook fn to remove loaded policy */
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
 * __next_namespace - find the next namespace to list
 * @root: root namespace to stop search at (NOT NULL)
 * @ns: current ns position (NOT NULL)
 *
 * Find the next namespace from @ns under @root and handle all locking needed
 * while switching current namespace.
 *
 * Returns: next namespace or NULL if at last namespace under @root
 * NOTE: will not unlock root->lock
 */
static struct aa_namespace *__next_namespace(struct aa_namespace *root,
					     struct aa_namespace *ns)
{
	struct aa_namespace *parent;

	/* is next namespace a child */
	if (!list_empty(&ns->sub_ns)) {
		struct aa_namespace *next;
		next = list_first_entry(&ns->sub_ns, typeof(*ns), base.list);
		read_lock(&next->lock);
		return next;
	}

	/* check if the next ns is a sibling, parent, gp, .. */
	parent = ns->parent;
	while (parent) {
		read_unlock(&ns->lock);
		list_for_each_entry_continue(ns, &parent->sub_ns, base.list) {
			read_lock(&ns->lock);
			return ns;
		}
		if (parent == root)
			return NULL;
		ns = parent;
		parent = parent->parent;
	}

	return NULL;
}

/**
 * __first_profile - find the first profile in a namespace
 * @root: namespace that is root of profiles being displayed (NOT NULL)
 * @ns: namespace to start in   (NOT NULL)
 *
 * Returns: unrefcounted profile or NULL if no profile
 */
	static struct aa_profile *__first_profile(struct aa_namespace *root,
						  struct aa_namespace *ns)
{
	for ( ; ns; ns = __next_namespace(root, ns)) {
		if (!list_empty(&ns->base.profiles))
			return list_first_entry(&ns->base.profiles,
						struct aa_profile, base.list);
	}
	return NULL;
}

/**
 * __next_profile - step to the next profile in a profile tree
 * @profile: current profile in tree (NOT NULL)
 *
 * Perform a depth first taversal on the profile tree in a namespace
 *
 * Returns: next profile or NULL if done
 * Requires: profile->ns.lock to be held
 */
static struct aa_profile *__next_profile(struct aa_profile *p)
{
	struct aa_profile *parent;
	struct aa_namespace *ns = p->ns;

	/* is next profile a child */
	if (!list_empty(&p->base.profiles))
		return list_first_entry(&p->base.profiles, typeof(*p),
					base.list);

	/* is next profile a sibling, parent sibling, gp, subling, .. */
	parent = p->parent;
	while (parent) {
		list_for_each_entry_continue(p, &parent->base.profiles,
					     base.list)
				return p;
		p = parent;
		parent = parent->parent;
	}

	/* is next another profile in the namespace */
	list_for_each_entry_continue(p, &ns->base.profiles, base.list)
		return p;

	return NULL;
}

/**
 * next_profile - step to the next profile in where ever it may be
 * @root: root namespace  (NOT NULL)
 * @profile: current profile  (NOT NULL)
 *
 * Returns: next profile or NULL if there isn't one
 */
static struct aa_profile *next_profile(struct aa_namespace *root,
				       struct aa_profile *profile)
{
	struct aa_profile *next = __next_profile(profile);
	if (next)
		return next;

	/* finished all profiles in namespace move to next namespace */
	return __first_profile(root, __next_namespace(root, profile->ns));
}

/**
 * p_start - start a depth first traversal of profile tree
 * @f: seq_file to fill
 * @pos: current position
 *
 * Returns: first profile under current namespace or NULL if none found
 *
 * acquires first ns->lock
 */
static void *p_start(struct seq_file *f, loff_t *pos)
	__acquires(root->lock)
{
	struct aa_profile *profile = NULL;
	struct aa_namespace *root = aa_current_profile()->ns;
	loff_t l = *pos;
	f->private = aa_get_namespace(root);


	/* find the first profile */
	read_lock(&root->lock);
	profile = __first_profile(root, root);

	/* skip to position */
	for (; profile && l > 0; l--)
		profile = next_profile(root, profile);

	return profile;
}

/**
 * p_next - read the next profile entry
 * @f: seq_file to fill
 * @p: profile previously returned
 * @pos: current position
 *
 * Returns: next profile after @p or NULL if none
 *
 * may acquire/release locks in namespace tree as necessary
 */
static void *p_next(struct seq_file *f, void *p, loff_t *pos)
{
	struct aa_profile *profile = p;
	struct aa_namespace *root = f->private;
	(*pos)++;

	return next_profile(root, profile);
}

/**
 * p_stop - stop depth first traversal
 * @f: seq_file we are filling
 * @p: the last profile writen
 *
 * Release all locking done by p_start/p_next on namespace tree
 */
static void p_stop(struct seq_file *f, void *p)
	__releases(root->lock)
{
	struct aa_profile *profile = p;
	struct aa_namespace *root = f->private, *ns;

	if (profile) {
		for (ns = profile->ns; ns && ns != root; ns = ns->parent)
			read_unlock(&ns->lock);
	}
	read_unlock(&root->lock);
	aa_put_namespace(root);
}

/**
 * print_ns_name - print a namespace name back to @root
 * @root: root namespace to stop at
 * @ns: namespace to gen name for
 *
 * Returns: true if it printed a name
 */
static bool print_ns_name(struct seq_file *f, struct aa_namespace *root,
			  struct aa_namespace *ns)
{
	if (!ns || ns == root)
		return 0;

	if (ns->parent && print_ns_name(f, root, ns->parent))
		seq_printf(f, "//");

	seq_printf(f, "%s", ns->base.name);
	return 1;
}

/**
 * seq_show_profile - 
 * @f: seq_file to file
 * @p: current position (profile)    (NOT NULL)
 *
 * Returns: error on failure
 */
static int seq_show_profile(struct seq_file *f, void *p)
{
	struct aa_profile *profile = (struct aa_profile *)p;
	struct aa_namespace *root = f->private;

	if (profile->ns != root)
		seq_printf(f, ":");
	if (print_ns_name(f, root, profile->ns))
		seq_printf(f, "://");
	seq_printf(f, "%s (%s)\n", profile->base.hname,
		   COMPLAIN_MODE(profile) ? "complain" : "enforce");

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
	return error;
}

fs_initcall(aa_create_aafs);
