/*
 * AppArmor security module
 *
 * This file contains AppArmor function for pathnames
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include <linux/mnt_namespace.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/fs_struct.h>

#include "include/apparmor.h"
#include "include/path.h"
#include "include/policy.h"

/**
 * d_namespace_path - lookup a name associated with a given path
 * @path: path to lookup
 * @buf:  buffer to store path to
 * @buflen: length of @buf
 * @name: returns pointer for start of path name with in @buf
 * @flags: flags controling path lookup
 *
 */
static int d_namespace_path(struct path *path, char *buf, int buflen,
			    char **name, int flags)
{
	struct path root, tmp, ns_root = { };
	char *res;
	int deleted;
	int error = 0;

	read_lock(&current->fs->lock);
	root = current->fs->root;
	/* released below */
	path_get(&current->fs->root);
	read_unlock(&current->fs->lock);
	spin_lock(&vfsmount_lock);
	if (root.mnt && root.mnt->mnt_ns)
		/* released below */
		ns_root.mnt = mntget(root.mnt->mnt_ns->root);
	if (ns_root.mnt)
		/* released below */
		ns_root.dentry = dget(ns_root.mnt->mnt_root);
	spin_unlock(&vfsmount_lock);
	spin_lock(&dcache_lock);

	/* There is a race window between path lookup here and the
	 * need to strip the " (deleted) string that __d_path applies
	 * Detect the race and relookup the path
	 */
	do {
		tmp = ns_root;
		deleted = d_unlinked(path->dentry);
		res = __d_path(path, &tmp, buf, buflen);

	} while (deleted != d_unlinked(path->dentry));

	*name = res;
	/* handle error conditions - and still allow a partial path to
	 * be returned.
	 */
	if (IS_ERR(res)) {
		error = PTR_ERR(res);
		*name = buf;
	} else if (deleted) {
		/* The stripping of (deleted) is a hack that could be removed
		 * with an updated __d_path
		 */

		if (!path->dentry->d_inode || flags & PFLAG_DELETED_NAMES)
			/* On some filesystems, newly allocated dentries appear
			 * to the security_path hooks as a deleted
			 * dentry except without an inode allocated.
			 *
			 * Remove the appended deleted text and return as a
			 * string for normal mediation.  The (deleted) string
			 * is guarenteed to be added in this case, so just
			 * strip it.
			 */
			buf[buflen - 11] = 0;	/* - (len(" (deleted)") +\0) */
		else
			error = -ENOENT;
	} else if (flags & ~PFLAG_CONNECT_PATH &&
		   tmp.dentry != ns_root.dentry && tmp.mnt != ns_root.mnt) {
		/* disconnected path, don't return pathname starting with '/' */
		error = -ESTALE;
		if (*res == '/')
			*name = res + 1;
	}

	spin_unlock(&dcache_lock);
	path_put(&root);
	path_put(&ns_root);

	return error;
}

static int get_name_to_buffer(struct path *path, int is_dir, char *buffer,
			      int size, char **name, int flags)
{
	int error = d_namespace_path(path, buffer, size - is_dir, name, flags);

	if (!error && is_dir && (*name)[1] != '\0')
		/*
		 * Append "/" to the pathname.  The root directory is a special
		 * case; it already ends in slash.
		 */
		strcpy(&buffer[size - 2], "/");

	return error;
}

/**
 * aa_get_name - compute the pathname of a file
 * @path: path the file
 * @is_dir: set if the file is a directory
 * @buffer: buffer that aa_get_name() allocated
 * @name: the error code indicating whether aa_get_name failed
 *
 * Returns an error code if the there was a failure in obtaining the
 * name.
 *
 * @name is apointer to the beginning of the pathname (which usually differs
 * from the beginning of the buffer), or NULL.  If there is an error @name
 * may contain a partial or invalid name (in the case of a deleted file), that
 * can be used for audit purposes, but it can not be used for mediation.
 *
 * We need @is_dir to indicate whether the file is a directory or not because
 * the file may not yet exist, and so we cannot check the inode's file type.
 */
int aa_get_name(struct path *path, int is_dir, char **buffer, char **name)
{
	char *buf, *str = NULL;
	int size = 256;
	int error;

	*name = NULL;
	*buffer = NULL;
	for (;;) {
		/* freed by caller */
		buf = kmalloc(size, GFP_KERNEL);
		if (!buf)
			return -ENOMEM;

		error = get_name_to_buffer(path, is_dir, buf, size, &str, 0);
		if (!error || (error == -ENOENT) || (error == -ESTALE))
			break;

		kfree(buf);
		size <<= 1;
		if (size > aa_g_path_max)
			return -ENAMETOOLONG;
	}
	*buffer = buf;
	*name = str;

	return error;
}

char *sysctl_pathname(struct ctl_table *table, char *buffer, int buflen)
{
	if (buflen < 1)
		return NULL;
	buffer += --buflen;
	*buffer = '\0';

	while (table) {
		int namelen = strlen(table->procname);

		if (buflen < namelen + 1)
			return NULL;
		buflen -= namelen + 1;
		buffer -= namelen;
		memcpy(buffer, table->procname, namelen);
		*--buffer = '/';
		table = table->parent;
	}
	if (buflen < 4)
		return NULL;
	buffer -= 4;
	memcpy(buffer, "/sys", 4);

	return buffer;
}
