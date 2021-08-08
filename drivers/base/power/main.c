/*
 * drivers/base/power/main.c - Where the driver meets power management.
 *
 * Copyright (c) 2003 Patrick Mochel
 * Copyright (c) 2003 Open Source Development Lab
 *
 * This file is released under the GPLv2
 *
 *
 * The driver model core calls device_pm_add() when a device is registered.
 * This will intialize the embedded device_pm_info object in the device
 * and add it to the list of power-controlled devices. sysfs entries for
 * controlling device power management will also be added.
 *
 * A different set of lists than the global subsystem list are used to
 * keep track of power info because we use different lists to hold
 * devices based on what stage of the power management process they
 * are in. The power domain dependencies may also differ from the
 * ancestral dependencies that the subsystem list maintains.
 */

#include <linux/device.h>
#include <linux/kallsyms.h>
#include <linux/mutex.h>
#include <linux/pm.h>
#include <linux/resume-trace.h>
#include <linux/rwsem.h>

#include "../base.h"
#include "power.h"

/*
 * The entries in the dpm_active list are in a depth first order, simply
 * because children are guaranteed to be discovered after parents, and
 * are inserted at the back of the list on discovery.
 *
 * All the other lists are kept in the same order, for consistency.
 * However the lists aren't always traversed in the same order.
 * Semaphores must be acquired from the top (i.e., front) down
 * and released in the opposite order.  Devices must be suspended
 * from the bottom (i.e., end) up and resumed in the opposite order.
 * That way no parent will be suspended while it still has an active
 * child.
 *
 * Since device_pm_add() may be called with a device semaphore held,
 * we must never try to acquire a device semaphore while holding
 * dpm_list_mutex.
 */

LIST_HEAD(dpm_active);
static LIST_HEAD(dpm_off);
static LIST_HEAD(dpm_off_irq);

static DEFINE_MUTEX(dpm_list_mtx);

/* 'true' if all devices have been suspended, protected by dpm_list_mtx */
static bool all_sleeping;

/**
 *	device_pm_add - add a device to the list of active devices
 *	@dev:	Device to be added to the list
 */
int device_pm_add(struct device *dev)
{
	int error;

	pr_debug("PM: Adding info for %s:%s\n",
		 dev->bus ? dev->bus->name : "No Bus",
		 kobject_name(&dev->kobj));
	mutex_lock(&dpm_list_mtx);
	if ((dev->parent && dev->parent->power.sleeping) || all_sleeping) {
		if (dev->parent->power.sleeping)
			dev_warn(dev, "parent %s is sleeping\n",
				dev->parent->bus_id);
		else
			dev_warn(dev, "all devices are sleeping\n");
		WARN_ON(true);
	}
	error = dpm_sysfs_add(dev);
	if (!error)
		list_add_tail(&dev->power.entry, &dpm_active);
	mutex_unlock(&dpm_list_mtx);
	return error;
}

/**
 *	device_pm_remove - remove a device from the list of active devices
 *	@dev:	Device to be removed from the list
 *
 *	This function also removes the device's PM-related sysfs attributes.
 */
void device_pm_remove(struct device *dev)
{
	pr_debug("PM: Removing info for %s:%s\n",
		 dev->bus ? dev->bus->name : "No Bus",
		 kobject_name(&dev->kobj));
	mutex_lock(&dpm_list_mtx);
	dpm_sysfs_remove(dev);
	list_del_init(&dev->power.entry);
	mutex_unlock(&dpm_list_mtx);
}

/*------------------------- Resume routines -------------------------*/

/**
 *	resume_device_early - Power on one device (early resume).
 *	@dev:	Device.
 *
 *	Must be called with interrupts disabled.
 */
static int resume_device_early(struct device *dev)
{
	int error = 0;

	TRACE_DEVICE(dev);
	TRACE_RESUME(0);

	if (dev->bus && dev->bus->resume_early) {
		dev_dbg(dev, "EARLY resume\n");
		error = dev->bus->resume_early(dev);
	}

	TRACE_RESUME(error);
	return error;
}

/**
 *	dpm_power_up - Power on all regular (non-sysdev) devices.
 *
 *	Walk the dpm_off_irq list and power each device up. This
 *	is used for devices that required they be powered down with
 *	interrupts disabled. As devices are powered on, they are moved
 *	to the dpm_off list.
 *
 *	Must be called with interrupts disabled and only one CPU running.
 */
static void dpm_power_up(void)
{

	while (!list_empty(&dpm_off_irq)) {
		struct list_head *entry = dpm_off_irq.next;
		struct device *dev = to_device(entry);

		list_move_tail(entry, &dpm_off);
		resume_device_early(dev);
	}
}

/**
 *	device_power_up - Turn on all devices that need special attention.
 *
 *	Power on system devices, then devices that required we shut them down
 *	with interrupts disabled.
 *
 *	Must be called with interrupts disabled.
 */
void device_power_up(void)
{
	sysdev_resume();
	dpm_power_up();
}
EXPORT_SYMBOL_GPL(device_power_up);

/**
 *	resume_device - Restore state for one device.
 *	@dev:	Device.
 *
 */
static int resume_device(struct device *dev)
{
	int error = 0;

	TRACE_DEVICE(dev);
	TRACE_RESUME(0);

	down(&dev->sem);

	if (dev->bus && dev->bus->resume) {
		dev_dbg(dev,"resuming\n");
		error = dev->bus->resume(dev);
	}

	if (!error && dev->type && dev->type->resume) {
		dev_dbg(dev,"resuming\n");
		error = dev->type->resume(dev);
	}

	if (!error && dev->class && dev->class->resume) {
		dev_dbg(dev,"class resume\n");
		error = dev->class->resume(dev);
	}

	up(&dev->sem);

	TRACE_RESUME(error);
	return error;
}

/**
 *	dpm_resume - Resume every device.
 *
 *	Resume the devices that have either not gone through
 *	the late suspend, or that did go through it but also
 *	went through the early resume.
 *
 *	Take devices from the dpm_off_list, resume them,
 *	and put them on the dpm_locked list.
 */
static void dpm_resume(void)
{
	mutex_lock(&dpm_list_mtx);
	all_sleeping = false;
	while(!list_empty(&dpm_off)) {
		struct list_head *entry = dpm_off.next;
		struct device *dev = to_device(entry);

		list_move_tail(entry, &dpm_active);
		dev->power.sleeping = false;
		mutex_unlock(&dpm_list_mtx);
		resume_device(dev);
		mutex_lock(&dpm_list_mtx);
	}
	mutex_unlock(&dpm_list_mtx);
}

/**
 *	device_resume - Restore state of each device in system.
 *
 *	Resume all the devices, unlock them all, and allow new
 *	devices to be registered once again.
 */
void device_resume(void)
{
	might_sleep();
	dpm_resume();
}
EXPORT_SYMBOL_GPL(device_resume);


/*------------------------- Suspend routines -------------------------*/

static inline char *suspend_verb(u32 event)
{
	switch (event) {
	case PM_EVENT_SUSPEND:	return "suspend";
	case PM_EVENT_FREEZE:	return "freeze";
	case PM_EVENT_PRETHAW:	return "prethaw";
	default:		return "(unknown suspend event)";
	}
}

static void
suspend_device_dbg(struct device *dev, pm_message_t state, char *info)
{
	dev_dbg(dev, "%s%s%s\n", info, suspend_verb(state.event),
		((state.event == PM_EVENT_SUSPEND) && device_may_wakeup(dev)) ?
		", may wakeup" : "");
}

/**
 *	suspend_device_late - Shut down one device (late suspend).
 *	@dev:	Device.
 *	@state:	Power state device is entering.
 *
 *	This is called with interrupts off and only a single CPU running.
 */
static int suspend_device_late(struct device *dev, pm_message_t state)
{
	int error = 0;

	if (dev->bus && dev->bus->suspend_late) {
		suspend_device_dbg(dev, state, "LATE ");
		error = dev->bus->suspend_late(dev, state);
		suspend_report_result(dev->bus->suspend_late, error);
	}
	return error;
}

/**
 *	device_power_down - Shut down special devices.
 *	@state:		Power state to enter.
 *
 *	Power down devices that require interrupts to be disabled
 *	and move them from the dpm_off list to the dpm_off_irq list.
 *	Then power down system devices.
 *
 *	Must be called with interrupts disabled and only one CPU running.
 */
int device_power_down(pm_message_t state)
{
	int error = 0;

	while (!list_empty(&dpm_off)) {
		struct list_head *entry = dpm_off.prev;
		struct device *dev = to_device(entry);

		error = suspend_device_late(dev, state);
		if (error) {
			printk(KERN_ERR "Could not power down device %s: "
					"error %d\n",
					kobject_name(&dev->kobj), error);
			break;
		}
		if (!list_empty(&dev->power.entry))
			list_move(&dev->power.entry, &dpm_off_irq);
	}

	if (!error)
		error = sysdev_suspend(state);
	if (error)
		dpm_power_up();
	return error;
}
EXPORT_SYMBOL_GPL(device_power_down);

/**
 *	suspend_device - Save state of one device.
 *	@dev:	Device.
 *	@state:	Power state device is entering.
 */
static int suspend_device(struct device *dev, pm_message_t state)
{
	int error = 0;

	down(&dev->sem);

	if (dev->class && dev->class->suspend) {
		suspend_device_dbg(dev, state, "class ");
		error = dev->class->suspend(dev, state);
		suspend_report_result(dev->class->suspend, error);
	}

	if (!error && dev->type && dev->type->suspend) {
		suspend_device_dbg(dev, state, "type ");
		error = dev->type->suspend(dev, state);
		suspend_report_result(dev->type->suspend, error);
	}

	if (!error && dev->bus && dev->bus->suspend) {
		suspend_device_dbg(dev, state, "");
		error = dev->bus->suspend(dev, state);
		suspend_report_result(dev->bus->suspend, error);
	}

	up(&dev->sem);

	return error;
}

/**
 *	dpm_suspend - Suspend every device.
 *	@state:	Power state to put each device in.
 *
 *	Walk the dpm_locked list.  Suspend each device and move it
 *	to the dpm_off list.
 *
 *	(For historical reasons, if it returns -EAGAIN, that used to mean
 *	that the device would be called again with interrupts disabled.
 *	These days, we use the "suspend_late()" callback for that, so we
 *	print a warning and consider it an error).
 */
static int dpm_suspend(pm_message_t state)
{
	int error = 0;

	mutex_lock(&dpm_list_mtx);
	while (!list_empty(&dpm_active)) {
		struct list_head *entry = dpm_active.prev;
		struct device *dev = to_device(entry);

		WARN_ON(dev->parent && dev->parent->power.sleeping);

		dev->power.sleeping = true;
		mutex_unlock(&dpm_list_mtx);
		error = suspend_device(dev, state);
		mutex_lock(&dpm_list_mtx);
		if (error) {
			printk(KERN_ERR "Could not suspend device %s: "
					"error %d%s\n",
					kobject_name(&dev->kobj),
					error,
					(error == -EAGAIN ?
					" (please convert to suspend_late)" :
					""));
			dev->power.sleeping = false;
			break;
		}
		if (!list_empty(&dev->power.entry))
			list_move(&dev->power.entry, &dpm_off);
	}
	if (!error)
		all_sleeping = true;
	mutex_unlock(&dpm_list_mtx);

	return error;
}

/**
 *	device_suspend - Save state and stop all devices in system.
 *	@state: new power management state
 *
 *	Prevent new devices from being registered, then lock all devices
 *	and suspend them.
 */
int device_suspend(pm_message_t state)
{
	int error;

	might_sleep();
	error = dpm_suspend(state);
	if (error)
		device_resume();
	return error;
}
EXPORT_SYMBOL_GPL(device_suspend);

void __suspend_report_result(const char *function, void *fn, int ret)
{
	if (ret) {
		printk(KERN_ERR "%s(): ", function);
		print_fn_descriptor_symbol("%s returns ", fn);
		printk("%d\n", ret);
	}
}
EXPORT_SYMBOL_GPL(__suspend_report_result);
