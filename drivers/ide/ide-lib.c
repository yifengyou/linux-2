#include <linux/module.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/timer.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/major.h>
#include <linux/errno.h>
#include <linux/genhd.h>
#include <linux/blkpg.h>
#include <linux/slab.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/hdreg.h>
#include <linux/ide.h>
#include <linux/bitops.h>

#include <asm/byteorder.h>
#include <asm/irq.h>
#include <asm/uaccess.h>
#include <asm/io.h>

static const char *udma_str[] =
	 { "UDMA/16", "UDMA/25",  "UDMA/33",  "UDMA/44",
	   "UDMA/66", "UDMA/100", "UDMA/133", "UDMA7" };
static const char *mwdma_str[] =
	{ "MWDMA0", "MWDMA1", "MWDMA2" };
static const char *swdma_str[] =
	{ "SWDMA0", "SWDMA1", "SWDMA2" };
static const char *pio_str[] =
	{ "PIO0", "PIO1", "PIO2", "PIO3", "PIO4", "PIO5" };

/**
 *	ide_xfer_verbose	-	return IDE mode names
 *	@mode: transfer mode
 *
 *	Returns a constant string giving the name of the mode
 *	requested.
 */

const char *ide_xfer_verbose(u8 mode)
{
	const char *s;
	u8 i = mode & 0xf;

	if (mode >= XFER_UDMA_0 && mode <= XFER_UDMA_7)
		s = udma_str[i];
	else if (mode >= XFER_MW_DMA_0 && mode <= XFER_MW_DMA_2)
		s = mwdma_str[i];
	else if (mode >= XFER_SW_DMA_0 && mode <= XFER_SW_DMA_2)
		s = swdma_str[i];
	else if (mode >= XFER_PIO_0 && mode <= XFER_PIO_5)
		s = pio_str[i & 0x7];
	else if (mode == XFER_PIO_SLOW)
		s = "PIO SLOW";
	else
		s = "XFER ERROR";

	return s;
}

EXPORT_SYMBOL(ide_xfer_verbose);

/**
 *	ide_rate_filter		-	filter transfer mode
 *	@drive: IDE device
 *	@speed: desired speed
 *
 *	Given the available transfer modes this function returns
 *	the best available speed at or below the speed requested.
 *
 *	TODO: check device PIO capabilities
 */

static u8 ide_rate_filter(ide_drive_t *drive, u8 speed)
{
	ide_hwif_t *hwif = drive->hwif;
	u8 mode = ide_find_dma_mode(drive, speed);

	if (mode == 0) {
		if (hwif->pio_mask)
			mode = fls(hwif->pio_mask) - 1 + XFER_PIO_0;
		else
			mode = XFER_PIO_4;
	}

/*	printk("%s: mode 0x%02x, speed 0x%02x\n", __func__, mode, speed); */

	return min(speed, mode);
}

/*
 * Standard (generic) timings for PIO modes, from ATA2 specification.
 * These timings are for access to the IDE data port register *only*.
 * Some drives may specify a mode, while also specifying a different
 * value for cycle_time (from drive identification data).
 */
const ide_pio_timings_t ide_pio_timings[6] = {
	{ 70,	165,	600 },	/* PIO Mode 0 */
	{ 50,	125,	383 },	/* PIO Mode 1 */
	{ 30,	100,	240 },	/* PIO Mode 2 */
	{ 30,	80,	180 },	/* PIO Mode 3 with IORDY */
	{ 25,	70,	120 },	/* PIO Mode 4 with IORDY */
	{ 20,	50,	100 }	/* PIO Mode 5 with IORDY (nonstandard) */
};

EXPORT_SYMBOL_GPL(ide_pio_timings);

/*
 * Shared data/functions for determining best PIO mode for an IDE drive.
 * Most of this stuff originally lived in cmd640.c, and changes to the
 * ide_pio_blacklist[] table should be made with EXTREME CAUTION to avoid
 * breaking the fragile cmd640.c support.
 */

/*
 * Black list. Some drives incorrectly report their maximal PIO mode,
 * at least in respect to CMD640. Here we keep info on some known drives.
 */
static struct ide_pio_info {
	const char	*name;
	int		pio;
} ide_pio_blacklist [] = {
	{ "Conner Peripherals 540MB - CFS540A", 3 },

	{ "WDC AC2700",  3 },
	{ "WDC AC2540",  3 },
	{ "WDC AC2420",  3 },
	{ "WDC AC2340",  3 },
	{ "WDC AC2250",  0 },
	{ "WDC AC2200",  0 },
	{ "WDC AC21200", 4 },
	{ "WDC AC2120",  0 },
	{ "WDC AC2850",  3 },
	{ "WDC AC1270",  3 },
	{ "WDC AC1170",  1 },
	{ "WDC AC1210",  1 },
	{ "WDC AC280",   0 },
	{ "WDC AC31000", 3 },
	{ "WDC AC31200", 3 },

	{ "Maxtor 7131 AT", 1 },
	{ "Maxtor 7171 AT", 1 },
	{ "Maxtor 7213 AT", 1 },
	{ "Maxtor 7245 AT", 1 },
	{ "Maxtor 7345 AT", 1 },
	{ "Maxtor 7546 AT", 3 },
	{ "Maxtor 7540 AV", 3 },

	{ "SAMSUNG SHD-3121A", 1 },
	{ "SAMSUNG SHD-3122A", 1 },
	{ "SAMSUNG SHD-3172A", 1 },

	{ "ST5660A",  3 },
	{ "ST3660A",  3 },
	{ "ST3630A",  3 },
	{ "ST3655A",  3 },
	{ "ST3391A",  3 },
	{ "ST3390A",  1 },
	{ "ST3600A",  1 },
	{ "ST3290A",  0 },
	{ "ST3144A",  0 },
	{ "ST3491A",  1 },	/* reports 3, should be 1 or 2 (depending on */	
				/* drive) according to Seagates FIND-ATA program */

	{ "QUANTUM ELS127A", 0 },
	{ "QUANTUM ELS170A", 0 },
	{ "QUANTUM LPS240A", 0 },
	{ "QUANTUM LPS210A", 3 },
	{ "QUANTUM LPS270A", 3 },
	{ "QUANTUM LPS365A", 3 },
	{ "QUANTUM LPS540A", 3 },
	{ "QUANTUM LIGHTNING 540A", 3 },
	{ "QUANTUM LIGHTNING 730A", 3 },

        { "QUANTUM FIREBALL_540", 3 }, /* Older Quantum Fireballs don't work */
        { "QUANTUM FIREBALL_640", 3 }, 
        { "QUANTUM FIREBALL_1080", 3 },
        { "QUANTUM FIREBALL_1280", 3 },
	{ NULL,	0 }
};

/**
 *	ide_scan_pio_blacklist 	-	check for a blacklisted drive
 *	@model: Drive model string
 *
 *	This routine searches the ide_pio_blacklist for an entry
 *	matching the start/whole of the supplied model name.
 *
 *	Returns -1 if no match found.
 *	Otherwise returns the recommended PIO mode from ide_pio_blacklist[].
 */

static int ide_scan_pio_blacklist (char *model)
{
	struct ide_pio_info *p;

	for (p = ide_pio_blacklist; p->name != NULL; p++) {
		if (strncmp(p->name, model, strlen(p->name)) == 0)
			return p->pio;
	}
	return -1;
}

unsigned int ide_pio_cycle_time(ide_drive_t *drive, u8 pio)
{
	struct hd_driveid *id = drive->id;
	int cycle_time = 0;

	if (id->field_valid & 2) {
		if (id->capability & 8)
			cycle_time = id->eide_pio_iordy;
		else
			cycle_time = id->eide_pio;
	}

	/* conservative "downgrade" for all pre-ATA2 drives */
	if (pio < 3) {
		if (cycle_time && cycle_time < ide_pio_timings[pio].cycle_time)
			cycle_time = 0; /* use standard timing */
	}

	return cycle_time ? cycle_time : ide_pio_timings[pio].cycle_time;
}

EXPORT_SYMBOL_GPL(ide_pio_cycle_time);

/**
 *	ide_get_best_pio_mode	-	get PIO mode from drive
 *	@drive: drive to consider
 *	@mode_wanted: preferred mode
 *	@max_mode: highest allowed mode
 *
 *	This routine returns the recommended PIO settings for a given drive,
 *	based on the drive->id information and the ide_pio_blacklist[].
 *
 *	Drive PIO mode is auto-selected if 255 is passed as mode_wanted.
 *	This is used by most chipset support modules when "auto-tuning".
 */

u8 ide_get_best_pio_mode (ide_drive_t *drive, u8 mode_wanted, u8 max_mode)
{
	int pio_mode;
	struct hd_driveid* id = drive->id;
	int overridden  = 0;

	if (mode_wanted != 255)
		return min_t(u8, mode_wanted, max_mode);

	if ((drive->hwif->host_flags & IDE_HFLAG_PIO_NO_BLACKLIST) == 0 &&
	    (pio_mode = ide_scan_pio_blacklist(id->model)) != -1) {
		printk(KERN_INFO "%s: is on PIO blacklist\n", drive->name);
	} else {
		pio_mode = id->tPIO;
		if (pio_mode > 2) {	/* 2 is maximum allowed tPIO value */
			pio_mode = 2;
			overridden = 1;
		}
		if (id->field_valid & 2) {	  /* drive implements ATA2? */
			if (id->capability & 8) { /* IORDY supported? */
				if (id->eide_pio_modes & 7) {
					overridden = 0;
					if (id->eide_pio_modes & 4)
						pio_mode = 5;
					else if (id->eide_pio_modes & 2)
						pio_mode = 4;
					else
						pio_mode = 3;
				}
			}
		}

		if (overridden)
			printk(KERN_INFO "%s: tPIO > 2, assuming tPIO = 2\n",
					 drive->name);
	}

	if (pio_mode > max_mode)
		pio_mode = max_mode;

	return pio_mode;
}

EXPORT_SYMBOL_GPL(ide_get_best_pio_mode);

/* req_pio == "255" for auto-tune */
void ide_set_pio(ide_drive_t *drive, u8 req_pio)
{
	ide_hwif_t *hwif = drive->hwif;
	const struct ide_port_ops *port_ops = hwif->port_ops;
	u8 host_pio, pio;

	if (port_ops == NULL || port_ops->set_pio_mode == NULL ||
	    (hwif->host_flags & IDE_HFLAG_NO_SET_MODE))
		return;

	BUG_ON(hwif->pio_mask == 0x00);

	host_pio = fls(hwif->pio_mask) - 1;

	pio = ide_get_best_pio_mode(drive, req_pio, host_pio);

	/*
	 * TODO:
	 * - report device max PIO mode
	 * - check req_pio != 255 against device max PIO mode
	 */
	printk(KERN_DEBUG "%s: host max PIO%d wanted PIO%d%s selected PIO%d\n",
			  drive->name, host_pio, req_pio,
			  req_pio == 255 ? "(auto-tune)" : "", pio);

	(void)ide_set_pio_mode(drive, XFER_PIO_0 + pio);
}

EXPORT_SYMBOL_GPL(ide_set_pio);

/**
 *	ide_toggle_bounce	-	handle bounce buffering
 *	@drive: drive to update
 *	@on: on/off boolean
 *
 *	Enable or disable bounce buffering for the device. Drives move
 *	between PIO and DMA and that changes the rules we need.
 */
 
void ide_toggle_bounce(ide_drive_t *drive, int on)
{
	u64 addr = BLK_BOUNCE_HIGH;	/* dma64_addr_t */

	if (!PCI_DMA_BUS_IS_PHYS) {
		addr = BLK_BOUNCE_ANY;
	} else if (on && drive->media == ide_disk) {
		struct device *dev = drive->hwif->dev;

		if (dev && dev->dma_mask)
			addr = *dev->dma_mask;
	}

	if (drive->queue)
		blk_queue_bounce_limit(drive->queue, addr);
}

int ide_set_pio_mode(ide_drive_t *drive, const u8 mode)
{
	ide_hwif_t *hwif = drive->hwif;
	const struct ide_port_ops *port_ops = hwif->port_ops;

	if (hwif->host_flags & IDE_HFLAG_NO_SET_MODE)
		return 0;

	if (port_ops == NULL || port_ops->set_pio_mode == NULL)
		return -1;

	/*
	 * TODO: temporary hack for some legacy host drivers that didn't
	 * set transfer mode on the device in ->set_pio_mode method...
	 */
	if (port_ops->set_dma_mode == NULL) {
		port_ops->set_pio_mode(drive, mode - XFER_PIO_0);
		return 0;
	}

	if (hwif->host_flags & IDE_HFLAG_POST_SET_MODE) {
		if (ide_config_drive_speed(drive, mode))
			return -1;
		port_ops->set_pio_mode(drive, mode - XFER_PIO_0);
		return 0;
	} else {
		port_ops->set_pio_mode(drive, mode - XFER_PIO_0);
		return ide_config_drive_speed(drive, mode);
	}
}

int ide_set_dma_mode(ide_drive_t *drive, const u8 mode)
{
	ide_hwif_t *hwif = drive->hwif;
	const struct ide_port_ops *port_ops = hwif->port_ops;

	if (hwif->host_flags & IDE_HFLAG_NO_SET_MODE)
		return 0;

	if (port_ops == NULL || port_ops->set_dma_mode == NULL)
		return -1;

	if (hwif->host_flags & IDE_HFLAG_POST_SET_MODE) {
		if (ide_config_drive_speed(drive, mode))
			return -1;
		port_ops->set_dma_mode(drive, mode);
		return 0;
	} else {
		port_ops->set_dma_mode(drive, mode);
		return ide_config_drive_speed(drive, mode);
	}
}

EXPORT_SYMBOL_GPL(ide_set_dma_mode);

/**
 *	ide_set_xfer_rate	-	set transfer rate
 *	@drive: drive to set
 *	@rate: speed to attempt to set
 *	
 *	General helper for setting the speed of an IDE device. This
 *	function knows about user enforced limits from the configuration
 *	which ->set_pio_mode/->set_dma_mode does not.
 */

int ide_set_xfer_rate(ide_drive_t *drive, u8 rate)
{
	ide_hwif_t *hwif = drive->hwif;
	const struct ide_port_ops *port_ops = hwif->port_ops;

	if (port_ops == NULL || port_ops->set_dma_mode == NULL ||
	    (hwif->host_flags & IDE_HFLAG_NO_SET_MODE))
		return -1;

	rate = ide_rate_filter(drive, rate);

	if (rate >= XFER_PIO_0 && rate <= XFER_PIO_5)
		return ide_set_pio_mode(drive, rate);

	/*
	 * TODO: transfer modes 0x00-0x07 passed from the user-space are
	 * currently handled here which needs fixing (please note that such
	 * case could happen iff the transfer mode has already been set on
	 * the device by ide-proc.c::set_xfer_rate()).
	 */
	if (rate < XFER_PIO_0) {
		if (hwif->host_flags & IDE_HFLAG_ABUSE_SET_DMA_MODE)
			return ide_set_dma_mode(drive, rate);
		else
			return ide_config_drive_speed(drive, rate);
	}

	return ide_set_dma_mode(drive, rate);
}

static void ide_dump_opcode(ide_drive_t *drive)
{
	struct request *rq;
	ide_task_t *task = NULL;

	spin_lock(&ide_lock);
	rq = NULL;
	if (HWGROUP(drive))
		rq = HWGROUP(drive)->rq;
	spin_unlock(&ide_lock);
	if (!rq)
		return;

	if (rq->cmd_type == REQ_TYPE_ATA_TASKFILE)
		task = rq->special;

	printk("ide: failed opcode was: ");
	if (task == NULL)
		printk(KERN_CONT "unknown\n");
	else
		printk(KERN_CONT "0x%02x\n", task->tf.command);
}

u64 ide_get_lba_addr(struct ide_taskfile *tf, int lba48)
{
	u32 high, low;

	if (lba48)
		high = (tf->hob_lbah << 16) | (tf->hob_lbam << 8) |
			tf->hob_lbal;
	else
		high = tf->device & 0xf;
	low  = (tf->lbah << 16) | (tf->lbam << 8) | tf->lbal;

	return ((u64)high << 24) | low;
}
EXPORT_SYMBOL_GPL(ide_get_lba_addr);

static void ide_dump_sector(ide_drive_t *drive)
{
	ide_task_t task;
	struct ide_taskfile *tf = &task.tf;
	int lba48 = (drive->addressing == 1) ? 1 : 0;

	memset(&task, 0, sizeof(task));
	if (lba48)
		task.tf_flags = IDE_TFLAG_IN_LBA | IDE_TFLAG_IN_HOB_LBA |
				IDE_TFLAG_LBA48;
	else
		task.tf_flags = IDE_TFLAG_IN_LBA | IDE_TFLAG_IN_DEVICE;

	drive->hwif->tf_read(drive, &task);

	if (lba48 || (tf->device & ATA_LBA))
		printk(", LBAsect=%llu",
			(unsigned long long)ide_get_lba_addr(tf, lba48));
	else
		printk(", CHS=%d/%d/%d", (tf->lbah << 8) + tf->lbam,
					 tf->device & 0xf, tf->lbal);
}

static void ide_dump_ata_error(ide_drive_t *drive, u8 err)
{
	printk("{ ");
	if (err & ABRT_ERR)	printk("DriveStatusError ");
	if (err & ICRC_ERR)
		printk((err & ABRT_ERR) ? "BadCRC " : "BadSector ");
	if (err & ECC_ERR)	printk("UncorrectableError ");
	if (err & ID_ERR)	printk("SectorIdNotFound ");
	if (err & TRK0_ERR)	printk("TrackZeroNotFound ");
	if (err & MARK_ERR)	printk("AddrMarkNotFound ");
	printk("}");
	if ((err & (BBD_ERR | ABRT_ERR)) == BBD_ERR ||
	    (err & (ECC_ERR|ID_ERR|MARK_ERR))) {
		ide_dump_sector(drive);
		if (HWGROUP(drive) && HWGROUP(drive)->rq)
			printk(", sector=%llu",
			       (unsigned long long)HWGROUP(drive)->rq->sector);
	}
	printk("\n");
}

static void ide_dump_atapi_error(ide_drive_t *drive, u8 err)
{
	printk("{ ");
	if (err & ILI_ERR)	printk("IllegalLengthIndication ");
	if (err & EOM_ERR)	printk("EndOfMedia ");
	if (err & ABRT_ERR)	printk("AbortedCommand ");
	if (err & MCR_ERR)	printk("MediaChangeRequested ");
	if (err & LFS_ERR)	printk("LastFailedSense=0x%02x ",
				       (err & LFS_ERR) >> 4);
	printk("}\n");
}

/**
 *	ide_dump_status		-	translate ATA/ATAPI error
 *	@drive: drive that status applies to
 *	@msg: text message to print
 *	@stat: status byte to decode
 *
 *	Error reporting, in human readable form (luxurious, but a memory hog).
 *	Combines the drive name, message and status byte to provide a
 *	user understandable explanation of the device error.
 */

u8 ide_dump_status(ide_drive_t *drive, const char *msg, u8 stat)
{
	unsigned long flags;
	u8 err = 0;

	local_irq_save(flags);
	printk("%s: %s: status=0x%02x { ", drive->name, msg, stat);
	if (stat & BUSY_STAT)
		printk("Busy ");
	else {
		if (stat & READY_STAT)	printk("DriveReady ");
		if (stat & WRERR_STAT)	printk("DeviceFault ");
		if (stat & SEEK_STAT)	printk("SeekComplete ");
		if (stat & DRQ_STAT)	printk("DataRequest ");
		if (stat & ECC_STAT)	printk("CorrectedError ");
		if (stat & INDEX_STAT)	printk("Index ");
		if (stat & ERR_STAT)	printk("Error ");
	}
	printk("}\n");
	if ((stat & (BUSY_STAT|ERR_STAT)) == ERR_STAT) {
		err = ide_read_error(drive);
		printk("%s: %s: error=0x%02x ", drive->name, msg, err);
		if (drive->media == ide_disk)
			ide_dump_ata_error(drive, err);
		else
			ide_dump_atapi_error(drive, err);
	}
	ide_dump_opcode(drive);
	local_irq_restore(flags);
	return err;
}

EXPORT_SYMBOL(ide_dump_status);
