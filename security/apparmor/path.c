/*
 * AppArmor security module
 *
 * This file contains AppArmor function for pathnames
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2010 Canonical Ltd.
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
	int deleted, connected;
	int error = 0;

	read_lock(&current->fs->lock);
	root = current->fs->root;
	/* released below */
	path_get(&root);
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
	 *
	 * The stripping of (deleted) is a hack that could be removed
	 * with an updated __d_path
	 */
	do {
		if (flags & PATH_CHROOT_REL)
			tmp = root;
		else
			tmp = ns_root;
		deleted = d_unlinked(path->dentry);
		res = __d_path(path, &tmp, buf, buflen);

	} while (deleted != d_unlinked(path->dentry));
	spin_unlock(&dcache_lock);

	*name = res;
	/* handle error conditions - and still allow a partial path to
	 * be returned.
	 */
	if (IS_ERR(res)) {
		error = PTR_ERR(res);
		*name = buf;
		goto out;
	}
	if (deleted) {
		/* On some filesystems, newly allocated dentries appear to the
		 * security_path hooks as a deleted dentry except without an
		 * inode allocated.
		 *
		 * Remove the appended deleted text and return as string for
		 * normal mediation, or auditing.  The (deleted) string is
		 * guarenteed to be added in this case, so just strip it.
		 */
		buf[buflen - 11] = 0;	/* - (len(" (deleted)") +\0) */

		if (path->dentry->d_inode && !(flags & PATH_MEDIATE_DELETED)) {
			error = -ENOENT;
			goto out;
		}
	}

	if (flags & PATH_CHROOT_REL)
		connected = tmp.dentry == root.dentry && tmp.mnt == root.mnt;
	else
		connected = tmp.dentry == ns_root.dentry &&
			tmp.mnt == ns_root.mnt;

	if (!connected && 
	    !(flags & PATH_CONNECT_PATH) &&
	    !((flags & PATH_CHROOT_REL) && (flags & PATH_CHROOT_NSCONNECT) &&
	      (tmp.dentry == ns_root.dentry && tmp.mnt == ns_root.mnt))) {
		/* disconnected path, don't return pathname starting with '/' */
		error = -ESTALE;
		if (*res == '/')
			*name = res + 1;
	}

out:
	path_put(&root);
	path_put(&ns_root);

	return error;
}

static int get_name_to_buffer(struct path *path, int flags, char *buffer,
			      int size, char **name)
{
	int adjust = (flags & PATH_IS_DIR) ? 1 : 0;
	int error = d_namespace_path(path, buffer, size - adjust, name, flags);

	if (!error && (flags & PATH_IS_DIR) && (*name)[1] != '\0')
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
 * @flags: flags controling path name generation
 * @buffer: buffer that aa_get_name() allocated
 * @name: the generated path name if there is an error
 *
 * Returns an error code if the there was a failure in obtaining the
 * name.
 *
 * @name is a pointer to the beginning of the pathname (which usually differs
 * from the beginning of the buffer), or NULL.  If there is an error @name
 * may contain a partial or invalid name (in the case of a deleted file), that
 * can be used for audit purposes, but it can not be used for mediation.
 *
 * We need PATH_IS_DIR to indicate whether the file is a directory or not
 * because the file may not yet exist, and so we cannot check the inode's
 * file type.
 */
int aa_get_name(struct path *path, int flags, char **buffer, char **name)
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

		error = get_name_to_buffer(path, flags, buf, size, &str);
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
