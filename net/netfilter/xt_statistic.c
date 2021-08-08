/*
 * Copyright (c) 2006 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Based on ipt_random and ipt_nth by Fabrice MARIE <fabrice@netfilter.org>.
 */

#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/skbuff.h>
#include <linux/net.h>

#include <linux/netfilter/xt_statistic.h>
#include <linux/netfilter/x_tables.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Patrick McHardy <kaber@trash.net>");
MODULE_DESCRIPTION("Xtables: statistics-based matching (\"Nth\", random)");
MODULE_ALIAS("ipt_statistic");
MODULE_ALIAS("ip6t_statistic");

static DEFINE_SPINLOCK(nth_lock);

static bool
statistic_mt(const struct sk_buff *skb, const struct net_device *in,
             const struct net_device *out, const struct xt_match *match,
             const void *matchinfo, int offset, unsigned int protoff,
             bool *hotdrop)
{
	struct xt_statistic_info *info = (struct xt_statistic_info *)matchinfo;
	bool ret = info->flags & XT_STATISTIC_INVERT;

	switch (info->mode) {
	case XT_STATISTIC_MODE_RANDOM:
		if ((net_random() & 0x7FFFFFFF) < info->u.random.probability)
			ret = !ret;
		break;
	case XT_STATISTIC_MODE_NTH:
		info = info->master;
		spin_lock_bh(&nth_lock);
		if (info->u.nth.count++ == info->u.nth.every) {
			info->u.nth.count = 0;
			ret = !ret;
		}
		spin_unlock_bh(&nth_lock);
		break;
	}

	return ret;
}

static bool
statistic_mt_check(const char *tablename, const void *entry,
                   const struct xt_match *match, void *matchinfo,
                   unsigned int hook_mask)
{
	struct xt_statistic_info *info = matchinfo;

	if (info->mode > XT_STATISTIC_MODE_MAX ||
	    info->flags & ~XT_STATISTIC_MASK)
		return false;
	info->master = info;
	return true;
}

static struct xt_match statistic_mt_reg[] __read_mostly = {
	{
		.name		= "statistic",
		.family		= AF_INET,
		.checkentry	= statistic_mt_check,
		.match		= statistic_mt,
		.matchsize	= sizeof(struct xt_statistic_info),
		.me		= THIS_MODULE,
	},
	{
		.name		= "statistic",
		.family		= AF_INET6,
		.checkentry	= statistic_mt_check,
		.match		= statistic_mt,
		.matchsize	= sizeof(struct xt_statistic_info),
		.me		= THIS_MODULE,
	},
};

static int __init statistic_mt_init(void)
{
	return xt_register_matches(statistic_mt_reg,
	       ARRAY_SIZE(statistic_mt_reg));
}

static void __exit statistic_mt_exit(void)
{
	xt_unregister_matches(statistic_mt_reg,
	                      ARRAY_SIZE(statistic_mt_reg));
}

module_init(statistic_mt_init);
module_exit(statistic_mt_exit);
