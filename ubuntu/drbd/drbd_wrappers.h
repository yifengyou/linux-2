#include <linux/ctype.h>
#include <linux/mm.h>


/* see get_sb_bdev and bd_claim */
extern char *drbd_sec_holder;

static inline sector_t drbd_get_hardsect(struct block_device *bdev)
{
	return bdev_logical_block_size(bdev);
}

/* sets the number of 512 byte sectors of our virtual device */
static inline void drbd_set_my_capacity(struct drbd_conf *mdev,
					sector_t size)
{
	/* set_capacity(mdev->this_bdev->bd_disk, size); */
	set_capacity(mdev->vdisk, size);
	mdev->this_bdev->bd_inode->i_size = (loff_t)size << 9;
}

#define drbd_bio_uptodate(bio) bio_flagged(bio, BIO_UPTODATE)

static inline int drbd_bio_has_active_page(struct bio *bio)
{
	struct bio_vec *bvec;
	int i;

	__bio_for_each_segment(bvec, bio, i, 0) {
		if (page_count(bvec->bv_page) > 1)
			return 1;
	}

	return 0;
}

/* bi_end_io handlers */
extern void drbd_md_io_complete(struct bio *bio, int error);
extern void drbd_endio_read_sec(struct bio *bio, int error);
extern void drbd_endio_write_sec(struct bio *bio, int error);
extern void drbd_endio_pri(struct bio *bio, int error);

/* how to get to the kobj of a gendisk.
 * see also upstream commits
 * edfaa7c36574f1bf09c65ad602412db9da5f96bf
 * ed9e1982347b36573cd622ee5f4e2a7ccd79b3fd
 * 548b10eb2959c96cef6fc29fc96e0931eeb53bc5
 */
#ifndef dev_to_disk
# define disk_to_kobj(disk) (&(disk)->kobj)
#else
# ifndef disk_to_dev
#  define disk_to_dev(disk) (&(disk)->dev)
# endif
# define disk_to_kobj(disk) (&disk_to_dev(disk)->kobj)
#endif
static inline void drbd_kobject_uevent(struct drbd_conf *mdev)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,15)
	kobject_uevent(disk_to_kobj(mdev->vdisk), KOBJ_CHANGE, NULL);
#else
	kobject_uevent(disk_to_kobj(mdev->vdisk), KOBJ_CHANGE);
	/* rhel4 / sles9 and older don't have this at all,
	 * which means user space (udev) won't get events about possible changes of
	 * corresponding resource + disk names after the initial drbd minor creation.
	 */
#endif
#endif
}


/*
 * used to submit our private bio
 */
static inline void drbd_generic_make_request(struct drbd_conf *mdev,
					     int fault_type, struct bio *bio)
{
	__release(local);
	if (!bio->bi_bdev) {
		printk(KERN_ERR "drbd%d: drbd_generic_make_request: "
				"bio->bi_bdev == NULL\n",
		       mdev_to_minor(mdev));
		dump_stack();
		bio_endio(bio, -ENODEV);
		return;
	}

	if (FAULT_ACTIVE(mdev, fault_type))
		bio_endio(bio, -EIO);
	else
		generic_make_request(bio);
}

static inline void drbd_plug_device(struct drbd_conf *mdev)
{
	struct request_queue *q;
	q = bdev_get_queue(mdev->this_bdev);

	spin_lock_irq(q->queue_lock);

/* XXX the check on !blk_queue_plugged is redundant,
 * implicitly checked in blk_plug_device */

	if (!blk_queue_plugged(q)) {
		blk_plug_device(q);
		del_timer(&q->unplug_timer);
		/* unplugging should not happen automatically... */
	}
	spin_unlock_irq(q->queue_lock);
}

#ifndef __CHECKER__
# undef __cond_lock
# define __cond_lock(x,c) (c)
#endif
