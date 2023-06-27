/*
 * AppArmor security module
 *
 * This file contains AppArmor filesystem definitions.
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2010 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#ifndef __AA_APPARMORFS_H
#define __AA_APPARMORFS_H

extern struct dentry *aa_fs_null;
extern struct vfsmount *aa_fs_mnt;

extern void aa_destroy_aafs(void);

#ifdef CONFIG_SECURITY_APPARMOR_COMPAT_24
extern const struct file_operations aa_fs_matching_fops;
extern const struct file_operations aa_fs_features_fops;
#endif

#endif /* __AA_APPARMORFS_H */
