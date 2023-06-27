/*
 * Target device file I/O.
 * (C) 2004 - 2005 FUJITA Tomonori <tomof@acm.org>
 * This code is licenced under the GPL.
 */

#include <linux/types.h>
#include <linux/blkdev.h>
#include <linux/parser.h>
#include <linux/writeback.h>

#include "iscsi.h"
#include "iscsi_dbg.h"
#include "iotype.h"

struct fileio_data {
	char *path;
	struct file *filp;
};

static int fileio_make_request(struct iet_volume *lu, struct tio *tio, int rw)
{
	struct fileio_data *p = lu->private;
	struct file *filp;
	mm_segment_t oldfs;
	struct page *page;
	u32 offset, size;
	loff_t ppos, count;
	char *buf;
	int i, err = 0;
	ssize_t ret;

	assert(p);
	filp = p->filp;
	size = tio->size;
	offset= tio->offset;

	ppos = (loff_t) tio->idx << PAGE_CACHE_SHIFT;
	ppos += offset;

	for (i = 0; i < tio->pg_cnt; i++) {
		page = tio->pvec[i];
		assert(page);
		buf = page_address(page);
		buf += offset;

		if (offset + size > PAGE_CACHE_SIZE)
			count = PAGE_CACHE_SIZE - offset;
		else
			count = size;

		oldfs = get_fs();
		set_fs(get_ds());

		if (rw == READ)
			ret = do_sync_read(filp, buf, count, &ppos);
		else
			ret = do_sync_write(filp, buf, count, &ppos);

		set_fs(oldfs);

		if (ret != count) {
			eprintk("I/O error %lld, %ld\n", count, (long) ret);
			err = -EIO;
		}

		size -= count;
		offset = 0;
	}
	assert(!size);

	return err;
}

static int fileio_sync(struct iet_volume *lu, struct tio *tio)
{
	struct fileio_data *p = lu->private;
	struct inode *inode = p->filp->f_dentry->d_inode;
	struct address_space *mapping = inode->i_mapping;
	loff_t ppos, count;
	int res;

	if (tio) {
		ppos = (loff_t) tio->idx << PAGE_CACHE_SHIFT;
		count = tio->size;
	} else {
		ppos = 0;
		count = lu->blk_cnt << lu->blk_shift;
	}

	res = filemap_write_and_wait_range(mapping, ppos, ppos + count - 1);
	if (res) {
		eprintk("I/O error: syncing pages failed: %d\n", res);
		return -EIO;
	} else
		return 0;
}

static int open_path(struct iet_volume *volume, const char *path)
{
	int err = 0;
	struct fileio_data *info = volume->private;
	struct file *filp;
	mm_segment_t oldfs;
	int flags;

	info->path = kstrdup(path, GFP_KERNEL);
	if (!info->path)
		return -ENOMEM;

	oldfs = get_fs();
	set_fs(get_ds());
	flags = (LUReadonly(volume) ? O_RDONLY : O_RDWR) | O_LARGEFILE;
	filp = filp_open(path, flags, 0);
	set_fs(oldfs);

	if (IS_ERR(filp)) {
		err = PTR_ERR(filp);
		eprintk("Can't open %s %d\n", path, err);
		info->filp = NULL;
	} else
		info->filp = filp;

	return err;
}

static int set_scsiid(struct iet_volume *volume, const char *id)
{
	size_t len;

	if ((len = strlen(id)) > SCSI_ID_LEN - VENDOR_ID_LEN) {
		eprintk("SCSI ID too long, %zd provided, %u max\n", len,
			SCSI_ID_LEN - VENDOR_ID_LEN);
		return -EINVAL;
	}

	memcpy(volume->scsi_id + VENDOR_ID_LEN, id, len);

	return 0;
}

static void gen_scsiid(struct iet_volume *volume, struct inode *inode)
{
	int i;
	u32 *p;

	strlcpy(volume->scsi_id, VENDOR_ID, VENDOR_ID_LEN);

	for (i = VENDOR_ID_LEN; i < SCSI_ID_LEN; i++)
		if (volume->scsi_id[i])
			return;

	p = (u32 *) (volume->scsi_id + VENDOR_ID_LEN);
	*(p + 0) = volume->target->trgt_param.target_type;
	*(p + 1) = volume->target->tid;
	*(p + 2) = (unsigned int) inode->i_ino;
	*(p + 3) = (unsigned int) inode->i_sb->s_dev;
}

static int set_scsisn(struct iet_volume *volume, const char *sn)
{
	size_t len;

	if ((len = strlen(sn)) > SCSI_SN_LEN) {
		eprintk("SCSI SN too long, %zd provided, %u max\n", len,
			SCSI_SN_LEN);
		return -EINVAL;
	}
	memcpy(volume->scsi_sn, sn, len);
	return 0;
}

enum {
	Opt_scsiid, Opt_scsisn, Opt_path, Opt_ignore, Opt_err,
};

static match_table_t tokens = {
	{Opt_scsiid, "ScsiId=%s"},
	{Opt_scsisn, "ScsiSN=%s"},
	{Opt_path, "Path=%s"},
	{Opt_ignore, "Type=%s"},
	{Opt_ignore, "IOMode=%s"},
	{Opt_err, NULL},
};

static int parse_fileio_params(struct iet_volume *volume, char *params)
{
	struct fileio_data *info = volume->private;
	int err = 0;
	char *p, *q;

	while ((p = strsep(&params, ",")) != NULL) {
		substring_t args[MAX_OPT_ARGS];
		int token;
		if (!*p)
			continue;
		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_scsiid:
			if (!(q = match_strdup(&args[0]))) {
				err = -ENOMEM;
				goto out;
			}
			err = set_scsiid(volume, q);
			kfree(q);
			if (err < 0)
				goto out;
			break;
		case Opt_scsisn:
			if (!(q = match_strdup(&args[0]))) {
				err = -ENOMEM;
				goto out;
			}
			err = set_scsisn(volume, q);
			kfree(q);
			if (err < 0)
				goto out;
			break;
		case Opt_path:
			if (info->path) {
				iprintk("Target %s, LUN %u: "
					"duplicate \"Path\" param\n",
					volume->target->name, volume->lun);
				err = -EINVAL;
				goto out;
			}
			if (!(q = match_strdup(&args[0]))) {
				err = -ENOMEM;
				goto out;
			}
			err = open_path(volume, q);
			kfree(q);
			if (err < 0)
				goto out;
			break;
		case Opt_ignore:
			break;
		default:
			iprintk("Target %s, LUN %u: unknown param %s\n",
				volume->target->name, volume->lun, p);
			return -EINVAL;
		}
	}

	if (!info->path) {
		iprintk("Target %s, LUN %u: missing \"Path\" param\n",
			volume->target->name, volume->lun);
		err = -EINVAL;
	}
out:
	return err;
}

static void fileio_detach(struct iet_volume *lu)
{
	struct fileio_data *p = lu->private;

	kfree(p->path);
	if (p->filp)
		filp_close(p->filp, NULL);
	kfree(p);
	lu->private = NULL;
}

static int fileio_attach(struct iet_volume *lu, char *args)
{
	int err = 0;
	struct fileio_data *p;
	struct inode *inode;

	if (lu->private) {
		printk("already attached ? %d\n", lu->lun);
		return -EBUSY;
	}

	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	lu->private = p;

	if ((err = parse_fileio_params(lu, args)) < 0) {
		eprintk("%d\n", err);
		goto out;
	}
	inode = p->filp->f_dentry->d_inode;

	gen_scsiid(lu, inode);

	if (S_ISREG(inode->i_mode))
		;
	else if (S_ISBLK(inode->i_mode))
		inode = inode->i_bdev->bd_inode;
	else {
		err = -EINVAL;
		goto out;
	}

	lu->blk_shift = SECTOR_SIZE_BITS;
	lu->blk_cnt = inode->i_size >> lu->blk_shift;

	/* we're using the page cache */
	SetLURCache(lu);
out:
	if (err < 0)
		fileio_detach(lu);
	return err;
}

static void fileio_show(struct iet_volume *lu, struct seq_file *seq)
{
	struct fileio_data *p = lu->private;
	seq_printf(seq, " path:%s\n", p->path);
}

struct iotype fileio =
{
	.name = "fileio",
	.attach = fileio_attach,
	.make_request = fileio_make_request,
	.sync = fileio_sync,
	.detach = fileio_detach,
	.show = fileio_show,
};
