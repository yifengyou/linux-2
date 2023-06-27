/*
 * Target device block I/O.
 *
 * Based on file I/O driver from FUJITA Tomonori
 * (C) 2004 - 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2006 Andre Brinkmann <brinkman at hni dot upb dot de>
 * (C) 2007 Ross Walker <rswwalker at hotmail dot com>
 * (C) 2007 Ming Zhang <blackmagic02881 at gmail dot com>
 * This code is licenced under the GPL.
 */

#include <linux/types.h>
#include <linux/blkdev.h>
#include <linux/parser.h>
#include <linux/buffer_head.h>

#include "iscsi.h"
#include "iscsi_dbg.h"
#include "iotype.h"

struct blockio_data {
	char *path;
	struct block_device *bdev;
};

struct tio_work {
	atomic_t error;
	atomic_t bios_remaining;
	struct completion tio_complete;
};

static void blockio_bio_endio(struct bio *bio, int error)
{
	struct tio_work *tio_work = bio->bi_private;

	error = test_bit(BIO_UPTODATE, &bio->bi_flags) ? error : -EIO;

	if (error)
		atomic_set(&tio_work->error, error);

	/* If last bio signal completion */
	if (atomic_dec_and_test(&tio_work->bios_remaining))
		complete(&tio_work->tio_complete);

	bio_put(bio);
}

/*
 * Blockio_make_request(): The function translates an iscsi-request into
 * a number of requests to the corresponding block device.
 */
static int
blockio_make_request(struct iet_volume *volume, struct tio *tio, int rw)
{
	struct blockio_data *bio_data = volume->private;
	struct request_queue *bdev_q = bdev_get_queue(bio_data->bdev);
	struct tio_work *tio_work;
	struct bio *tio_bio = NULL, *bio = NULL, *biotail = NULL;

	u32 offset = tio->offset;
	u32 size = tio->size;
	u32 tio_index = 0;

	int max_pages = 1;
	int err = 0;

	loff_t ppos = ((loff_t) tio->idx << PAGE_SHIFT) + offset;

	/* Calculate max_pages for bio_alloc (memory saver) */
	if (bdev_q)
		max_pages = bio_get_nr_vecs(bio_data->bdev);

	tio_work = kzalloc(sizeof (*tio_work), GFP_KERNEL);
	if (!tio_work)
		return -ENOMEM;

	atomic_set(&tio_work->error, 0);
	atomic_set(&tio_work->bios_remaining, 0);
	init_completion(&tio_work->tio_complete);

	/* Main processing loop, allocate and fill all bios */
	while (tio_index < tio->pg_cnt) {
		bio = bio_alloc(GFP_KERNEL, min(max_pages, BIO_MAX_PAGES));
		if (!bio) {
			err = -ENOMEM;
			goto out;
		}

		bio->bi_sector = ppos >> volume->blk_shift;
		bio->bi_bdev = bio_data->bdev;
		bio->bi_end_io = blockio_bio_endio;
		bio->bi_private = tio_work;

		if (tio_bio)
			biotail = biotail->bi_next = bio;
		else
			tio_bio = biotail = bio;

		atomic_inc(&tio_work->bios_remaining);

		/* Loop for filling bio */
		while (tio_index < tio->pg_cnt) {
			unsigned int bytes = PAGE_SIZE - offset;

			if (bytes > size)
				bytes = size;

			if (!bio_add_page(bio, tio->pvec[tio_index], bytes, offset))
				break;

			size -= bytes;
			ppos += bytes;

			offset = 0;

			tio_index++;
		}
	}

	/* Walk the list, submitting bios 1 by 1 */
	while (tio_bio) {
		bio = tio_bio;
		tio_bio = tio_bio->bi_next;
		bio->bi_next = NULL;

		submit_bio(rw, bio);
	}

	if (bdev_q && bdev_q->unplug_fn)
		bdev_q->unplug_fn(bdev_q);

	wait_for_completion(&tio_work->tio_complete);

	err = atomic_read(&tio_work->error);

	kfree(tio_work);

	return err;
out:
	while (tio_bio) {
		bio = tio_bio;
		tio_bio = tio_bio->bi_next;

		bio_put(bio);
	}

	kfree(tio_work);

	return err;
}

static int
blockio_open_path(struct iet_volume *volume, const char *path)
{
	struct blockio_data *bio_data = volume->private;
	struct block_device *bdev;
	int flags = FMODE_READ | (LUReadonly(volume) ? 0 : FMODE_WRITE);
	int err = 0;

	bio_data->path = kstrdup(path, GFP_KERNEL);
	if (!bio_data->path)
		return -ENOMEM;

	bdev = open_bdev_exclusive(path, flags, THIS_MODULE);
	if (IS_ERR(bdev)) {
		err = PTR_ERR(bdev);
		eprintk("Can't open device %s, error %d\n", path, err);
		bio_data->bdev = NULL;
	} else {
		bio_data->bdev = bdev;
		fsync_bdev(bio_data->bdev);
	}

	return err;
}

static int
set_scsiid(struct iet_volume *volume, const char *id)
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

static void
gen_scsiid(struct iet_volume *volume, struct inode *inode)
{
	int i;
	u32 *p;

	strlcpy(volume->scsi_id, VENDOR_ID, VENDOR_ID_LEN);

	for (i = VENDOR_ID_LEN; i < SCSI_ID_LEN; i++)
		if (volume->scsi_id[i])
			return;

	/* If a scsi id doesn't exist generate a 16 byte one:
	 * Bytes   1-4: target type
	 * Bytes   5-8: target id
	 * Bytes  9-12: inode number
	 * Bytes 13-16: device type
	 */
	p = (u32 *) (volume->scsi_id + VENDOR_ID_LEN);
	*(p + 0) = volume->target->trgt_param.target_type;
	*(p + 1) = volume->target->tid;
	*(p + 2) = volume->lun;
	*(p + 3) = (unsigned int) inode->i_sb->s_dev;
}

static int
set_scsisn(struct iet_volume *volume, const char *sn)
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

/* Create an enumeration of our accepted actions */
enum
{
	Opt_scsiid, Opt_scsisn, Opt_path, Opt_ignore, Opt_err,
};

/* Create a match table using our action enums and their matching options */
static match_table_t tokens = {
	{Opt_scsiid, "ScsiId=%s"},
	{Opt_scsisn, "ScsiSN=%s"},
	{Opt_path, "Path=%s"},
	{Opt_ignore, "Type=%s"},
	{Opt_ignore, "IOMode=%s"},
	{Opt_err, NULL},
};

static int
parse_blockio_params(struct iet_volume *volume, char *params)
{
	struct blockio_data *info = volume->private;
	int err = 0;
	char *p, *q;

	/* Loop through parameters separated by commas, look up our
	 * parameter in match table, return enumeration and arguments
	 * select case based on the returned enum and run the action */
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
			err = blockio_open_path(volume, q);
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

static void
blockio_detach(struct iet_volume *volume)
{
	struct blockio_data *bio_data = volume->private;
	int flags = FMODE_READ | (LUReadonly(volume) ? 0 : FMODE_WRITE);

	if (bio_data->bdev)
		close_bdev_exclusive(bio_data->bdev, flags);
	kfree(bio_data->path);

	kfree(volume->private);
}

static int
blockio_attach(struct iet_volume *volume, char *args)
{
	struct blockio_data *bio_data;
	int err = 0;

	if (volume->private) {
		eprintk("Lun %u already attached on Target %s \n",
			volume->lun, volume->target->name);
		return -EBUSY;
	}

	bio_data = kzalloc(sizeof (*bio_data), GFP_KERNEL);
	if (!bio_data)
		return -ENOMEM;

	volume->private = bio_data;

	if ((err = parse_blockio_params(volume, args)) < 0) {
		eprintk("Error attaching Lun %u to Target %s \n",
			volume->lun, volume->target->name);
		goto out;
	}

	/* Assign a vendor id, generate scsi id if none exists */
	gen_scsiid(volume, bio_data->bdev->bd_inode);

	/* Offer neither write nor read caching */
	ClearLURCache(volume);
	ClearLUWCache(volume);

	volume->blk_shift = SECTOR_SIZE_BITS;
	volume->blk_cnt = bio_data->bdev->bd_inode->i_size >> volume->blk_shift;

  out:
	if (err < 0)
		blockio_detach(volume);

	return err;
}

static void
blockio_show(struct iet_volume *volume, struct seq_file *seq)
{
	struct blockio_data *bio_data = volume->private;

	/* Used to display blockio volume info in /proc/net/iet/volumes */
	seq_printf(seq, " path:%s\n", bio_data->path);
}

struct iotype blockio = {
	.name = "blockio",
	.attach = blockio_attach,
	.make_request = blockio_make_request,
	.detach = blockio_detach,
	.show = blockio_show,
};
