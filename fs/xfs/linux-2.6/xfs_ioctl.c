/*
 * Copyright (c) 2000-2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it would be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write the Free Software Foundation,
 * Inc.,  51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include "xfs.h"
#include "xfs_fs.h"
#include "xfs_bit.h"
#include "xfs_log.h"
#include "xfs_inum.h"
#include "xfs_trans.h"
#include "xfs_sb.h"
#include "xfs_ag.h"
#include "xfs_dir2.h"
#include "xfs_alloc.h"
#include "xfs_dmapi.h"
#include "xfs_mount.h"
#include "xfs_bmap_btree.h"
#include "xfs_alloc_btree.h"
#include "xfs_ialloc_btree.h"
#include "xfs_attr_sf.h"
#include "xfs_dir2_sf.h"
#include "xfs_dinode.h"
#include "xfs_inode.h"
#include "xfs_btree.h"
#include "xfs_ialloc.h"
#include "xfs_rtalloc.h"
#include "xfs_itable.h"
#include "xfs_error.h"
#include "xfs_rw.h"
#include "xfs_acl.h"
#include "xfs_attr.h"
#include "xfs_bmap.h"
#include "xfs_buf_item.h"
#include "xfs_utils.h"
#include "xfs_dfrag.h"
#include "xfs_fsops.h"
#include "xfs_vnodeops.h"

#include <linux/capability.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/pagemap.h>

/*
 * xfs_find_handle maps from userspace xfs_fsop_handlereq structure to
 * a file or fs handle.
 *
 * XFS_IOC_PATH_TO_FSHANDLE
 *    returns fs handle for a mount point or path within that mount point
 * XFS_IOC_FD_TO_HANDLE
 *    returns full handle for a FD opened in user space
 * XFS_IOC_PATH_TO_HANDLE
 *    returns full handle for a path
 */
STATIC int
xfs_find_handle(
	unsigned int		cmd,
	void			__user *arg)
{
	int			hsize;
	xfs_handle_t		handle;
	xfs_fsop_handlereq_t	hreq;
	struct inode		*inode;

	if (copy_from_user(&hreq, arg, sizeof(hreq)))
		return -XFS_ERROR(EFAULT);

	memset((char *)&handle, 0, sizeof(handle));

	switch (cmd) {
	case XFS_IOC_PATH_TO_FSHANDLE:
	case XFS_IOC_PATH_TO_HANDLE: {
		struct nameidata	nd;
		int			error;

		error = user_path_walk_link((const char __user *)hreq.path, &nd);
		if (error)
			return error;

		ASSERT(nd.path.dentry);
		ASSERT(nd.path.dentry->d_inode);
		inode = igrab(nd.path.dentry->d_inode);
		path_put(&nd.path);
		break;
	}

	case XFS_IOC_FD_TO_HANDLE: {
		struct file	*file;

		file = fget(hreq.fd);
		if (!file)
		    return -EBADF;

		ASSERT(file->f_path.dentry);
		ASSERT(file->f_path.dentry->d_inode);
		inode = igrab(file->f_path.dentry->d_inode);
		fput(file);
		break;
	}

	default:
		ASSERT(0);
		return -XFS_ERROR(EINVAL);
	}

	if (inode->i_sb->s_magic != XFS_SB_MAGIC) {
		/* we're not in XFS anymore, Toto */
		iput(inode);
		return -XFS_ERROR(EINVAL);
	}

	switch (inode->i_mode & S_IFMT) {
	case S_IFREG:
	case S_IFDIR:
	case S_IFLNK:
		break;
	default:
		iput(inode);
		return -XFS_ERROR(EBADF);
	}

	/* now we can grab the fsid */
	memcpy(&handle.ha_fsid, XFS_I(inode)->i_mount->m_fixedfsid,
			sizeof(xfs_fsid_t));
	hsize = sizeof(xfs_fsid_t);

	if (cmd != XFS_IOC_PATH_TO_FSHANDLE) {
		xfs_inode_t	*ip = XFS_I(inode);
		int		lock_mode;

		/* need to get access to the xfs_inode to read the generation */
		lock_mode = xfs_ilock_map_shared(ip);

		/* fill in fid section of handle from inode */
		handle.ha_fid.fid_len = sizeof(xfs_fid_t) -
					sizeof(handle.ha_fid.fid_len);
		handle.ha_fid.fid_pad = 0;
		handle.ha_fid.fid_gen = ip->i_d.di_gen;
		handle.ha_fid.fid_ino = ip->i_ino;

		xfs_iunlock_map_shared(ip, lock_mode);

		hsize = XFS_HSIZE(handle);
	}

	/* now copy our handle into the user buffer & write out the size */
	if (copy_to_user(hreq.ohandle, &handle, hsize) ||
	    copy_to_user(hreq.ohandlen, &hsize, sizeof(__s32))) {
		iput(inode);
		return -XFS_ERROR(EFAULT);
	}

	iput(inode);
	return 0;
}


/*
 * Convert userspace handle data into inode.
 *
 * We use the fact that all the fsop_handlereq ioctl calls have a data
 * structure argument whose first component is always a xfs_fsop_handlereq_t,
 * so we can pass that sub structure into this handy, shared routine.
 *
 * If no error, caller must always iput the returned inode.
 */
STATIC int
xfs_vget_fsop_handlereq(
	xfs_mount_t		*mp,
	struct inode		*parinode,	/* parent inode pointer    */
	xfs_fsop_handlereq_t	*hreq,
	struct inode		**inode)
{
	void			__user *hanp;
	size_t			hlen;
	xfs_fid_t		*xfid;
	xfs_handle_t		*handlep;
	xfs_handle_t		handle;
	xfs_inode_t		*ip;
	xfs_ino_t		ino;
	__u32			igen;
	int			error;

	/*
	 * Only allow handle opens under a directory.
	 */
	if (!S_ISDIR(parinode->i_mode))
		return XFS_ERROR(ENOTDIR);

	hanp = hreq->ihandle;
	hlen = hreq->ihandlen;
	handlep = &handle;

	if (hlen < sizeof(handlep->ha_fsid) || hlen > sizeof(*handlep))
		return XFS_ERROR(EINVAL);
	if (copy_from_user(handlep, hanp, hlen))
		return XFS_ERROR(EFAULT);
	if (hlen < sizeof(*handlep))
		memset(((char *)handlep) + hlen, 0, sizeof(*handlep) - hlen);
	if (hlen > sizeof(handlep->ha_fsid)) {
		if (handlep->ha_fid.fid_len !=
		    (hlen - sizeof(handlep->ha_fsid) -
		            sizeof(handlep->ha_fid.fid_len)) ||
		    handlep->ha_fid.fid_pad)
			return XFS_ERROR(EINVAL);
	}

	/*
	 * Crack the handle, obtain the inode # & generation #
	 */
	xfid = (struct xfs_fid *)&handlep->ha_fid;
	if (xfid->fid_len == sizeof(*xfid) - sizeof(xfid->fid_len)) {
		ino  = xfid->fid_ino;
		igen = xfid->fid_gen;
	} else {
		return XFS_ERROR(EINVAL);
	}

	/*
	 * Get the XFS inode, building a Linux inode to go with it.
	 */
	error = xfs_iget(mp, NULL, ino, 0, XFS_ILOCK_SHARED, &ip, 0);
	if (error)
		return error;
	if (ip == NULL)
		return XFS_ERROR(EIO);
	if (ip->i_d.di_gen != igen) {
		xfs_iput_new(ip, XFS_ILOCK_SHARED);
		return XFS_ERROR(ENOENT);
	}

	xfs_iunlock(ip, XFS_ILOCK_SHARED);

	*inode = XFS_ITOV(ip);
	return 0;
}

STATIC int
xfs_open_by_handle(
	xfs_mount_t		*mp,
	void			__user *arg,
	struct file		*parfilp,
	struct inode		*parinode)
{
	int			error;
	int			new_fd;
	int			permflag;
	struct file		*filp;
	struct inode		*inode;
	struct dentry		*dentry;
	xfs_fsop_handlereq_t	hreq;

	if (!capable(CAP_SYS_ADMIN))
		return -XFS_ERROR(EPERM);
	if (copy_from_user(&hreq, arg, sizeof(xfs_fsop_handlereq_t)))
		return -XFS_ERROR(EFAULT);

	error = xfs_vget_fsop_handlereq(mp, parinode, &hreq, &inode);
	if (error)
		return -error;

	/* Restrict xfs_open_by_handle to directories & regular files. */
	if (!(S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode))) {
		iput(inode);
		return -XFS_ERROR(EINVAL);
	}

#if BITS_PER_LONG != 32
	hreq.oflags |= O_LARGEFILE;
#endif
	/* Put open permission in namei format. */
	permflag = hreq.oflags;
	if ((permflag+1) & O_ACCMODE)
		permflag++;
	if (permflag & O_TRUNC)
		permflag |= 2;

	if ((!(permflag & O_APPEND) || (permflag & O_TRUNC)) &&
	    (permflag & FMODE_WRITE) && IS_APPEND(inode)) {
		iput(inode);
		return -XFS_ERROR(EPERM);
	}

	if ((permflag & FMODE_WRITE) && IS_IMMUTABLE(inode)) {
		iput(inode);
		return -XFS_ERROR(EACCES);
	}

	/* Can't write directories. */
	if ( S_ISDIR(inode->i_mode) && (permflag & FMODE_WRITE)) {
		iput(inode);
		return -XFS_ERROR(EISDIR);
	}

	if ((new_fd = get_unused_fd()) < 0) {
		iput(inode);
		return new_fd;
	}

	dentry = d_alloc_anon(inode);
	if (dentry == NULL) {
		iput(inode);
		put_unused_fd(new_fd);
		return -XFS_ERROR(ENOMEM);
	}

	/* Ensure umount returns EBUSY on umounts while this file is open. */
	mntget(parfilp->f_path.mnt);

	/* Create file pointer. */
	filp = dentry_open(dentry, parfilp->f_path.mnt, hreq.oflags);
	if (IS_ERR(filp)) {
		put_unused_fd(new_fd);
		return -XFS_ERROR(-PTR_ERR(filp));
	}
	if (inode->i_mode & S_IFREG) {
		/* invisible operation should not change atime */
		filp->f_flags |= O_NOATIME;
		filp->f_op = &xfs_invis_file_operations;
	}

	fd_install(new_fd, filp);
	return new_fd;
}

/*
 * This is a copy from fs/namei.c:vfs_readlink(), except for removing it's
 * unused first argument.
 */
STATIC int
do_readlink(
	char __user		*buffer,
	int			buflen,
	const char		*link)
{
        int len;

	len = PTR_ERR(link);
	if (IS_ERR(link))
		goto out;

	len = strlen(link);
	if (len > (unsigned) buflen)
		len = buflen;
	if (copy_to_user(buffer, link, len))
		len = -EFAULT;
 out:
	return len;
}


STATIC int
xfs_readlink_by_handle(
	xfs_mount_t		*mp,
	void			__user *arg,
	struct inode		*parinode)
{
	struct inode		*inode;
	xfs_fsop_handlereq_t	hreq;
	__u32			olen;
	void			*link;
	int			error;

	if (!capable(CAP_SYS_ADMIN))
		return -XFS_ERROR(EPERM);
	if (copy_from_user(&hreq, arg, sizeof(xfs_fsop_handlereq_t)))
		return -XFS_ERROR(EFAULT);

	error = xfs_vget_fsop_handlereq(mp, parinode, &hreq, &inode);
	if (error)
		return -error;

	/* Restrict this handle operation to symlinks only. */
	if (!S_ISLNK(inode->i_mode)) {
		error = -XFS_ERROR(EINVAL);
		goto out_iput;
	}

	if (copy_from_user(&olen, hreq.ohandlen, sizeof(__u32))) {
		error = -XFS_ERROR(EFAULT);
		goto out_iput;
	}

	link = kmalloc(MAXPATHLEN+1, GFP_KERNEL);
	if (!link)
		goto out_iput;

	error = -xfs_readlink(XFS_I(inode), link);
	if (error)
		goto out_kfree;
	error = do_readlink(hreq.ohandle, olen, link);
	if (error)
		goto out_kfree;

 out_kfree:
	kfree(link);
 out_iput:
	iput(inode);
	return error;
}

STATIC int
xfs_fssetdm_by_handle(
	xfs_mount_t		*mp,
	void			__user *arg,
	struct inode		*parinode)
{
	int			error;
	struct fsdmidata	fsd;
	xfs_fsop_setdm_handlereq_t dmhreq;
	struct inode		*inode;

	if (!capable(CAP_MKNOD))
		return -XFS_ERROR(EPERM);
	if (copy_from_user(&dmhreq, arg, sizeof(xfs_fsop_setdm_handlereq_t)))
		return -XFS_ERROR(EFAULT);

	error = xfs_vget_fsop_handlereq(mp, parinode, &dmhreq.hreq, &inode);
	if (error)
		return -error;

	if (IS_IMMUTABLE(inode) || IS_APPEND(inode)) {
		error = -XFS_ERROR(EPERM);
		goto out;
	}

	if (copy_from_user(&fsd, dmhreq.data, sizeof(fsd))) {
		error = -XFS_ERROR(EFAULT);
		goto out;
	}

	error = -xfs_set_dmattrs(XFS_I(inode), fsd.fsd_dmevmask,
				 fsd.fsd_dmstate);

 out:
	iput(inode);
	return error;
}

STATIC int
xfs_attrlist_by_handle(
	xfs_mount_t		*mp,
	void			__user *arg,
	struct inode		*parinode)
{
	int			error;
	attrlist_cursor_kern_t	*cursor;
	xfs_fsop_attrlist_handlereq_t al_hreq;
	struct inode		*inode;
	char			*kbuf;

	if (!capable(CAP_SYS_ADMIN))
		return -XFS_ERROR(EPERM);
	if (copy_from_user(&al_hreq, arg, sizeof(xfs_fsop_attrlist_handlereq_t)))
		return -XFS_ERROR(EFAULT);
	if (al_hreq.buflen > XATTR_LIST_MAX)
		return -XFS_ERROR(EINVAL);

	error = xfs_vget_fsop_handlereq(mp, parinode, &al_hreq.hreq, &inode);
	if (error)
		goto out;

	kbuf = kmalloc(al_hreq.buflen, GFP_KERNEL);
	if (!kbuf)
		goto out_vn_rele;

	cursor = (attrlist_cursor_kern_t *)&al_hreq.pos;
	error = xfs_attr_list(XFS_I(inode), kbuf, al_hreq.buflen,
					al_hreq.flags, cursor);
	if (error)
		goto out_kfree;

	if (copy_to_user(al_hreq.buffer, kbuf, al_hreq.buflen))
		error = -EFAULT;

 out_kfree:
	kfree(kbuf);
 out_vn_rele:
	iput(inode);
 out:
	return -error;
}

STATIC int
xfs_attrmulti_attr_get(
	struct inode		*inode,
	char			*name,
	char			__user *ubuf,
	__uint32_t		*len,
	__uint32_t		flags)
{
	char			*kbuf;
	int			error = EFAULT;

	if (*len > XATTR_SIZE_MAX)
		return EINVAL;
	kbuf = kmalloc(*len, GFP_KERNEL);
	if (!kbuf)
		return ENOMEM;

	error = xfs_attr_get(XFS_I(inode), name, kbuf, (int *)len, flags);
	if (error)
		goto out_kfree;

	if (copy_to_user(ubuf, kbuf, *len))
		error = EFAULT;

 out_kfree:
	kfree(kbuf);
	return error;
}

STATIC int
xfs_attrmulti_attr_set(
	struct inode		*inode,
	char			*name,
	const char		__user *ubuf,
	__uint32_t		len,
	__uint32_t		flags)
{
	char			*kbuf;
	int			error = EFAULT;

	if (IS_IMMUTABLE(inode) || IS_APPEND(inode))
		return EPERM;
	if (len > XATTR_SIZE_MAX)
		return EINVAL;

	kbuf = kmalloc(len, GFP_KERNEL);
	if (!kbuf)
		return ENOMEM;

	if (copy_from_user(kbuf, ubuf, len))
		goto out_kfree;

	error = xfs_attr_set(XFS_I(inode), name, kbuf, len, flags);

 out_kfree:
	kfree(kbuf);
	return error;
}

STATIC int
xfs_attrmulti_attr_remove(
	struct inode		*inode,
	char			*name,
	__uint32_t		flags)
{
	if (IS_IMMUTABLE(inode) || IS_APPEND(inode))
		return EPERM;
	return xfs_attr_remove(XFS_I(inode), name, flags);
}

STATIC int
xfs_attrmulti_by_handle(
	xfs_mount_t		*mp,
	void			__user *arg,
	struct file		*parfilp,
	struct inode		*parinode)
{
	int			error;
	xfs_attr_multiop_t	*ops;
	xfs_fsop_attrmulti_handlereq_t am_hreq;
	struct inode		*inode;
	unsigned int		i, size;
	char			*attr_name;

	if (!capable(CAP_SYS_ADMIN))
		return -XFS_ERROR(EPERM);
	if (copy_from_user(&am_hreq, arg, sizeof(xfs_fsop_attrmulti_handlereq_t)))
		return -XFS_ERROR(EFAULT);

	error = xfs_vget_fsop_handlereq(mp, parinode, &am_hreq.hreq, &inode);
	if (error)
		goto out;

	error = E2BIG;
	size = am_hreq.opcount * sizeof(attr_multiop_t);
	if (!size || size > 16 * PAGE_SIZE)
		goto out_vn_rele;

	error = ENOMEM;
	ops = kmalloc(size, GFP_KERNEL);
	if (!ops)
		goto out_vn_rele;

	error = EFAULT;
	if (copy_from_user(ops, am_hreq.ops, size))
		goto out_kfree_ops;

	attr_name = kmalloc(MAXNAMELEN, GFP_KERNEL);
	if (!attr_name)
		goto out_kfree_ops;


	error = 0;
	for (i = 0; i < am_hreq.opcount; i++) {
		ops[i].am_error = strncpy_from_user(attr_name,
				ops[i].am_attrname, MAXNAMELEN);
		if (ops[i].am_error == 0 || ops[i].am_error == MAXNAMELEN)
			error = -ERANGE;
		if (ops[i].am_error < 0)
			break;

		switch (ops[i].am_opcode) {
		case ATTR_OP_GET:
			ops[i].am_error = xfs_attrmulti_attr_get(inode,
					attr_name, ops[i].am_attrvalue,
					&ops[i].am_length, ops[i].am_flags);
			break;
		case ATTR_OP_SET:
			ops[i].am_error = mnt_want_write(parfilp->f_path.mnt);
			if (ops[i].am_error)
				break;
			ops[i].am_error = xfs_attrmulti_attr_set(inode,
					attr_name, ops[i].am_attrvalue,
					ops[i].am_length, ops[i].am_flags);
			mnt_drop_write(parfilp->f_path.mnt);
			break;
		case ATTR_OP_REMOVE:
			ops[i].am_error = mnt_want_write(parfilp->f_path.mnt);
			if (ops[i].am_error)
				break;
			ops[i].am_error = xfs_attrmulti_attr_remove(inode,
					attr_name, ops[i].am_flags);
			mnt_drop_write(parfilp->f_path.mnt);
			break;
		default:
			ops[i].am_error = EINVAL;
		}
	}

	if (copy_to_user(am_hreq.ops, ops, size))
		error = XFS_ERROR(EFAULT);

	kfree(attr_name);
 out_kfree_ops:
	kfree(ops);
 out_vn_rele:
	iput(inode);
 out:
	return -error;
}

STATIC int
xfs_ioc_space(
	struct xfs_inode	*ip,
	struct inode		*inode,
	struct file		*filp,
	int			ioflags,
	unsigned int		cmd,
	void			__user *arg)
{
	xfs_flock64_t		bf;
	int			attr_flags = 0;
	int			error;

	if (inode->i_flags & (S_IMMUTABLE|S_APPEND))
		return -XFS_ERROR(EPERM);

	if (!(filp->f_mode & FMODE_WRITE))
		return -XFS_ERROR(EBADF);

	if (!S_ISREG(inode->i_mode))
		return -XFS_ERROR(EINVAL);

	if (copy_from_user(&bf, arg, sizeof(bf)))
		return -XFS_ERROR(EFAULT);

	if (filp->f_flags & (O_NDELAY|O_NONBLOCK))
		attr_flags |= ATTR_NONBLOCK;
	if (ioflags & IO_INVIS)
		attr_flags |= ATTR_DMI;

	error = xfs_change_file_space(ip, cmd, &bf, filp->f_pos,
					      NULL, attr_flags);
	return -error;
}

STATIC int
xfs_ioc_bulkstat(
	xfs_mount_t		*mp,
	unsigned int		cmd,
	void			__user *arg)
{
	xfs_fsop_bulkreq_t	bulkreq;
	int			count;	/* # of records returned */
	xfs_ino_t		inlast;	/* last inode number */
	int			done;
	int			error;

	/* done = 1 if there are more stats to get and if bulkstat */
	/* should be called again (unused here, but used in dmapi) */

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (XFS_FORCED_SHUTDOWN(mp))
		return -XFS_ERROR(EIO);

	if (copy_from_user(&bulkreq, arg, sizeof(xfs_fsop_bulkreq_t)))
		return -XFS_ERROR(EFAULT);

	if (copy_from_user(&inlast, bulkreq.lastip, sizeof(__s64)))
		return -XFS_ERROR(EFAULT);

	if ((count = bulkreq.icount) <= 0)
		return -XFS_ERROR(EINVAL);

	if (bulkreq.ubuffer == NULL)
		return -XFS_ERROR(EINVAL);

	if (cmd == XFS_IOC_FSINUMBERS)
		error = xfs_inumbers(mp, &inlast, &count,
					bulkreq.ubuffer, xfs_inumbers_fmt);
	else if (cmd == XFS_IOC_FSBULKSTAT_SINGLE)
		error = xfs_bulkstat_single(mp, &inlast,
						bulkreq.ubuffer, &done);
	else	/* XFS_IOC_FSBULKSTAT */
		error = xfs_bulkstat(mp, &inlast, &count,
			(bulkstat_one_pf)xfs_bulkstat_one, NULL,
			sizeof(xfs_bstat_t), bulkreq.ubuffer,
			BULKSTAT_FG_QUICK, &done);

	if (error)
		return -error;

	if (bulkreq.ocount != NULL) {
		if (copy_to_user(bulkreq.lastip, &inlast,
						sizeof(xfs_ino_t)))
			return -XFS_ERROR(EFAULT);

		if (copy_to_user(bulkreq.ocount, &count, sizeof(count)))
			return -XFS_ERROR(EFAULT);
	}

	return 0;
}

STATIC int
xfs_ioc_fsgeometry_v1(
	xfs_mount_t		*mp,
	void			__user *arg)
{
	xfs_fsop_geom_v1_t	fsgeo;
	int			error;

	error = xfs_fs_geometry(mp, (xfs_fsop_geom_t *)&fsgeo, 3);
	if (error)
		return -error;

	if (copy_to_user(arg, &fsgeo, sizeof(fsgeo)))
		return -XFS_ERROR(EFAULT);
	return 0;
}

STATIC int
xfs_ioc_fsgeometry(
	xfs_mount_t		*mp,
	void			__user *arg)
{
	xfs_fsop_geom_t		fsgeo;
	int			error;

	error = xfs_fs_geometry(mp, &fsgeo, 4);
	if (error)
		return -error;

	if (copy_to_user(arg, &fsgeo, sizeof(fsgeo)))
		return -XFS_ERROR(EFAULT);
	return 0;
}

/*
 * Linux extended inode flags interface.
 */

STATIC unsigned int
xfs_merge_ioc_xflags(
	unsigned int	flags,
	unsigned int	start)
{
	unsigned int	xflags = start;

	if (flags & FS_IMMUTABLE_FL)
		xflags |= XFS_XFLAG_IMMUTABLE;
	else
		xflags &= ~XFS_XFLAG_IMMUTABLE;
	if (flags & FS_APPEND_FL)
		xflags |= XFS_XFLAG_APPEND;
	else
		xflags &= ~XFS_XFLAG_APPEND;
	if (flags & FS_SYNC_FL)
		xflags |= XFS_XFLAG_SYNC;
	else
		xflags &= ~XFS_XFLAG_SYNC;
	if (flags & FS_NOATIME_FL)
		xflags |= XFS_XFLAG_NOATIME;
	else
		xflags &= ~XFS_XFLAG_NOATIME;
	if (flags & FS_NODUMP_FL)
		xflags |= XFS_XFLAG_NODUMP;
	else
		xflags &= ~XFS_XFLAG_NODUMP;

	return xflags;
}

STATIC unsigned int
xfs_di2lxflags(
	__uint16_t	di_flags)
{
	unsigned int	flags = 0;

	if (di_flags & XFS_DIFLAG_IMMUTABLE)
		flags |= FS_IMMUTABLE_FL;
	if (di_flags & XFS_DIFLAG_APPEND)
		flags |= FS_APPEND_FL;
	if (di_flags & XFS_DIFLAG_SYNC)
		flags |= FS_SYNC_FL;
	if (di_flags & XFS_DIFLAG_NOATIME)
		flags |= FS_NOATIME_FL;
	if (di_flags & XFS_DIFLAG_NODUMP)
		flags |= FS_NODUMP_FL;
	return flags;
}

STATIC int
xfs_ioc_fsgetxattr(
	xfs_inode_t		*ip,
	int			attr,
	void			__user *arg)
{
	struct fsxattr		fa;

	xfs_ilock(ip, XFS_ILOCK_SHARED);
	fa.fsx_xflags = xfs_ip2xflags(ip);
	fa.fsx_extsize = ip->i_d.di_extsize << ip->i_mount->m_sb.sb_blocklog;
	fa.fsx_projid = ip->i_d.di_projid;

	if (attr) {
		if (ip->i_afp) {
			if (ip->i_afp->if_flags & XFS_IFEXTENTS)
				fa.fsx_nextents = ip->i_afp->if_bytes /
							sizeof(xfs_bmbt_rec_t);
			else
				fa.fsx_nextents = ip->i_d.di_anextents;
		} else
			fa.fsx_nextents = 0;
	} else {
		if (ip->i_df.if_flags & XFS_IFEXTENTS)
			fa.fsx_nextents = ip->i_df.if_bytes /
						sizeof(xfs_bmbt_rec_t);
		else
			fa.fsx_nextents = ip->i_d.di_nextents;
	}
	xfs_iunlock(ip, XFS_ILOCK_SHARED);

	if (copy_to_user(arg, &fa, sizeof(fa)))
		return -EFAULT;
	return 0;
}

STATIC int
xfs_ioc_fssetxattr(
	xfs_inode_t		*ip,
	struct file		*filp,
	void			__user *arg)
{
	struct fsxattr		fa;
	struct bhv_vattr	*vattr;
	int			error;
	int			attr_flags;

	if (copy_from_user(&fa, arg, sizeof(fa)))
		return -EFAULT;

	vattr = kmalloc(sizeof(*vattr), GFP_KERNEL);
	if (unlikely(!vattr))
		return -ENOMEM;

	attr_flags = 0;
	if (filp->f_flags & (O_NDELAY|O_NONBLOCK))
		attr_flags |= ATTR_NONBLOCK;

	vattr->va_mask = XFS_AT_XFLAGS | XFS_AT_EXTSIZE | XFS_AT_PROJID;
	vattr->va_xflags  = fa.fsx_xflags;
	vattr->va_extsize = fa.fsx_extsize;
	vattr->va_projid  = fa.fsx_projid;

	error = -xfs_setattr(ip, vattr, attr_flags, NULL);
	if (!error)
		vn_revalidate(XFS_ITOV(ip));	/* update flags */
	kfree(vattr);
	return 0;
}

STATIC int
xfs_ioc_getxflags(
	xfs_inode_t		*ip,
	void			__user *arg)
{
	unsigned int		flags;

	flags = xfs_di2lxflags(ip->i_d.di_flags);
	if (copy_to_user(arg, &flags, sizeof(flags)))
		return -EFAULT;
	return 0;
}

STATIC int
xfs_ioc_setxflags(
	xfs_inode_t		*ip,
	struct file		*filp,
	void			__user *arg)
{
	struct bhv_vattr	*vattr;
	unsigned int		flags;
	int			attr_flags;
	int			error;

	if (copy_from_user(&flags, arg, sizeof(flags)))
		return -EFAULT;

	if (flags & ~(FS_IMMUTABLE_FL | FS_APPEND_FL | \
		      FS_NOATIME_FL | FS_NODUMP_FL | \
		      FS_SYNC_FL))
		return -EOPNOTSUPP;

	vattr = kmalloc(sizeof(*vattr), GFP_KERNEL);
	if (unlikely(!vattr))
		return -ENOMEM;

	attr_flags = 0;
	if (filp->f_flags & (O_NDELAY|O_NONBLOCK))
		attr_flags |= ATTR_NONBLOCK;

	vattr->va_mask = XFS_AT_XFLAGS;
	vattr->va_xflags = xfs_merge_ioc_xflags(flags, xfs_ip2xflags(ip));

	error = -xfs_setattr(ip, vattr, attr_flags, NULL);
	if (likely(!error))
		vn_revalidate(XFS_ITOV(ip));	/* update flags */
	kfree(vattr);
	return error;
}

STATIC int
xfs_ioc_getbmap(
	struct xfs_inode	*ip,
	int			ioflags,
	unsigned int		cmd,
	void			__user *arg)
{
	struct getbmap		bm;
	int			iflags;
	int			error;

	if (copy_from_user(&bm, arg, sizeof(bm)))
		return -XFS_ERROR(EFAULT);

	if (bm.bmv_count < 2)
		return -XFS_ERROR(EINVAL);

	iflags = (cmd == XFS_IOC_GETBMAPA ? BMV_IF_ATTRFORK : 0);
	if (ioflags & IO_INVIS)
		iflags |= BMV_IF_NO_DMAPI_READ;

	error = xfs_getbmap(ip, &bm, (struct getbmap __user *)arg+1, iflags);
	if (error)
		return -error;

	if (copy_to_user(arg, &bm, sizeof(bm)))
		return -XFS_ERROR(EFAULT);
	return 0;
}

STATIC int
xfs_ioc_getbmapx(
	struct xfs_inode	*ip,
	void			__user *arg)
{
	struct getbmapx		bmx;
	struct getbmap		bm;
	int			iflags;
	int			error;

	if (copy_from_user(&bmx, arg, sizeof(bmx)))
		return -XFS_ERROR(EFAULT);

	if (bmx.bmv_count < 2)
		return -XFS_ERROR(EINVAL);

	/*
	 * Map input getbmapx structure to a getbmap
	 * structure for xfs_getbmap.
	 */
	GETBMAP_CONVERT(bmx, bm);

	iflags = bmx.bmv_iflags;

	if (iflags & (~BMV_IF_VALID))
		return -XFS_ERROR(EINVAL);

	iflags |= BMV_IF_EXTENDED;

	error = xfs_getbmap(ip, &bm, (struct getbmapx __user *)arg+1, iflags);
	if (error)
		return -error;

	GETBMAP_CONVERT(bm, bmx);

	if (copy_to_user(arg, &bmx, sizeof(bmx)))
		return -XFS_ERROR(EFAULT);

	return 0;
}

int
xfs_ioctl(
	xfs_inode_t		*ip,
	struct file		*filp,
	int			ioflags,
	unsigned int		cmd,
	void			__user *arg)
{
	struct inode		*inode = filp->f_path.dentry->d_inode;
	xfs_mount_t		*mp = ip->i_mount;
	int			error;

	xfs_itrace_entry(XFS_I(inode));
	switch (cmd) {

	case XFS_IOC_ALLOCSP:
	case XFS_IOC_FREESP:
	case XFS_IOC_RESVSP:
	case XFS_IOC_UNRESVSP:
	case XFS_IOC_ALLOCSP64:
	case XFS_IOC_FREESP64:
	case XFS_IOC_RESVSP64:
	case XFS_IOC_UNRESVSP64:
		/*
		 * Only allow the sys admin to reserve space unless
		 * unwritten extents are enabled.
		 */
		if (!xfs_sb_version_hasextflgbit(&mp->m_sb) &&
		    !capable(CAP_SYS_ADMIN))
			return -EPERM;

		return xfs_ioc_space(ip, inode, filp, ioflags, cmd, arg);

	case XFS_IOC_DIOINFO: {
		struct dioattr	da;
		xfs_buftarg_t	*target =
			XFS_IS_REALTIME_INODE(ip) ?
			mp->m_rtdev_targp : mp->m_ddev_targp;

		da.d_mem = da.d_miniosz = 1 << target->bt_sshift;
		da.d_maxiosz = INT_MAX & ~(da.d_miniosz - 1);

		if (copy_to_user(arg, &da, sizeof(da)))
			return -XFS_ERROR(EFAULT);
		return 0;
	}

	case XFS_IOC_FSBULKSTAT_SINGLE:
	case XFS_IOC_FSBULKSTAT:
	case XFS_IOC_FSINUMBERS:
		return xfs_ioc_bulkstat(mp, cmd, arg);

	case XFS_IOC_FSGEOMETRY_V1:
		return xfs_ioc_fsgeometry_v1(mp, arg);

	case XFS_IOC_FSGEOMETRY:
		return xfs_ioc_fsgeometry(mp, arg);

	case XFS_IOC_GETVERSION:
		return put_user(inode->i_generation, (int __user *)arg);

	case XFS_IOC_FSGETXATTR:
		return xfs_ioc_fsgetxattr(ip, 0, arg);
	case XFS_IOC_FSGETXATTRA:
		return xfs_ioc_fsgetxattr(ip, 1, arg);
	case XFS_IOC_FSSETXATTR:
		return xfs_ioc_fssetxattr(ip, filp, arg);
	case XFS_IOC_GETXFLAGS:
		return xfs_ioc_getxflags(ip, arg);
	case XFS_IOC_SETXFLAGS:
		return xfs_ioc_setxflags(ip, filp, arg);

	case XFS_IOC_FSSETDM: {
		struct fsdmidata	dmi;

		if (copy_from_user(&dmi, arg, sizeof(dmi)))
			return -XFS_ERROR(EFAULT);

		error = xfs_set_dmattrs(ip, dmi.fsd_dmevmask,
				dmi.fsd_dmstate);
		return -error;
	}

	case XFS_IOC_GETBMAP:
	case XFS_IOC_GETBMAPA:
		return xfs_ioc_getbmap(ip, ioflags, cmd, arg);

	case XFS_IOC_GETBMAPX:
		return xfs_ioc_getbmapx(ip, arg);

	case XFS_IOC_FD_TO_HANDLE:
	case XFS_IOC_PATH_TO_HANDLE:
	case XFS_IOC_PATH_TO_FSHANDLE:
		return xfs_find_handle(cmd, arg);

	case XFS_IOC_OPEN_BY_HANDLE:
		return xfs_open_by_handle(mp, arg, filp, inode);

	case XFS_IOC_FSSETDM_BY_HANDLE:
		return xfs_fssetdm_by_handle(mp, arg, inode);

	case XFS_IOC_READLINK_BY_HANDLE:
		return xfs_readlink_by_handle(mp, arg, inode);

	case XFS_IOC_ATTRLIST_BY_HANDLE:
		return xfs_attrlist_by_handle(mp, arg, inode);

	case XFS_IOC_ATTRMULTI_BY_HANDLE:
		return xfs_attrmulti_by_handle(mp, arg, filp, inode);

	case XFS_IOC_SWAPEXT: {
		error = xfs_swapext((struct xfs_swapext __user *)arg);
		return -error;
	}

	case XFS_IOC_FSCOUNTS: {
		xfs_fsop_counts_t out;

		error = xfs_fs_counts(mp, &out);
		if (error)
			return -error;

		if (copy_to_user(arg, &out, sizeof(out)))
			return -XFS_ERROR(EFAULT);
		return 0;
	}

	case XFS_IOC_SET_RESBLKS: {
		xfs_fsop_resblks_t inout;
		__uint64_t	   in;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;

		if (copy_from_user(&inout, arg, sizeof(inout)))
			return -XFS_ERROR(EFAULT);

		/* input parameter is passed in resblks field of structure */
		in = inout.resblks;
		error = xfs_reserve_blocks(mp, &in, &inout);
		if (error)
			return -error;

		if (copy_to_user(arg, &inout, sizeof(inout)))
			return -XFS_ERROR(EFAULT);
		return 0;
	}

	case XFS_IOC_GET_RESBLKS: {
		xfs_fsop_resblks_t out;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;

		error = xfs_reserve_blocks(mp, NULL, &out);
		if (error)
			return -error;

		if (copy_to_user(arg, &out, sizeof(out)))
			return -XFS_ERROR(EFAULT);

		return 0;
	}

	case XFS_IOC_FSGROWFSDATA: {
		xfs_growfs_data_t in;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;

		if (copy_from_user(&in, arg, sizeof(in)))
			return -XFS_ERROR(EFAULT);

		error = xfs_growfs_data(mp, &in);
		return -error;
	}

	case XFS_IOC_FSGROWFSLOG: {
		xfs_growfs_log_t in;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;

		if (copy_from_user(&in, arg, sizeof(in)))
			return -XFS_ERROR(EFAULT);

		error = xfs_growfs_log(mp, &in);
		return -error;
	}

	case XFS_IOC_FSGROWFSRT: {
		xfs_growfs_rt_t in;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;

		if (copy_from_user(&in, arg, sizeof(in)))
			return -XFS_ERROR(EFAULT);

		error = xfs_growfs_rt(mp, &in);
		return -error;
	}

	case XFS_IOC_FREEZE:
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;

		if (inode->i_sb->s_frozen == SB_UNFROZEN)
			freeze_bdev(inode->i_sb->s_bdev);
		return 0;

	case XFS_IOC_THAW:
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		if (inode->i_sb->s_frozen != SB_UNFROZEN)
			thaw_bdev(inode->i_sb->s_bdev, inode->i_sb);
		return 0;

	case XFS_IOC_GOINGDOWN: {
		__uint32_t in;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;

		if (get_user(in, (__uint32_t __user *)arg))
			return -XFS_ERROR(EFAULT);

		error = xfs_fs_goingdown(mp, in);
		return -error;
	}

	case XFS_IOC_ERROR_INJECTION: {
		xfs_error_injection_t in;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;

		if (copy_from_user(&in, arg, sizeof(in)))
			return -XFS_ERROR(EFAULT);

		error = xfs_errortag_add(in.errtag, mp);
		return -error;
	}

	case XFS_IOC_ERROR_CLEARALL:
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;

		error = xfs_errortag_clearall(mp, 1);
		return -error;

	default:
		return -ENOTTY;
	}
}
