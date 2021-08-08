/*
 * netfilter module to enforce network quotas
 *
 * Sam Johnston <samj@samj.net>
 */
#include <linux/skbuff.h>
#include <linux/spinlock.h>

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_quota.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sam Johnston <samj@samj.net>");
MODULE_DESCRIPTION("Xtables: countdown quota match");
MODULE_ALIAS("ipt_quota");
MODULE_ALIAS("ip6t_quota");

static DEFINE_SPINLOCK(quota_lock);

static bool
quota_mt(const struct sk_buff *skb, const struct net_device *in,
         const struct net_device *out, const struct xt_match *match,
         const void *matchinfo, int offset, unsigned int protoff,
         bool *hotdrop)
{
	struct xt_quota_info *q =
		((const struct xt_quota_info *)matchinfo)->master;
	bool ret = q->flags & XT_QUOTA_INVERT;

	spin_lock_bh(&quota_lock);
	if (q->quota >= skb->len) {
		q->quota -= skb->len;
		ret = !ret;
	} else {
		/* we do not allow even small packets from now on */
		q->quota = 0;
	}
	spin_unlock_bh(&quota_lock);

	return ret;
}

static bool
quota_mt_check(const char *tablename, const void *entry,
               const struct xt_match *match, void *matchinfo,
               unsigned int hook_mask)
{
	struct xt_quota_info *q = matchinfo;

	if (q->flags & ~XT_QUOTA_MASK)
		return false;
	/* For SMP, we only want to use one set of counters. */
	q->master = q;
	return true;
}

static struct xt_match quota_mt_reg[] __read_mostly = {
	{
		.name		= "quota",
		.family		= AF_INET,
		.checkentry	= quota_mt_check,
		.match		= quota_mt,
		.matchsize	= sizeof(struct xt_quota_info),
		.me		= THIS_MODULE
	},
	{
		.name		= "quota",
		.family		= AF_INET6,
		.checkentry	= quota_mt_check,
		.match		= quota_mt,
		.matchsize	= sizeof(struct xt_quota_info),
		.me		= THIS_MODULE
	},
};

static int __init quota_mt_init(void)
{
	return xt_register_matches(quota_mt_reg, ARRAY_SIZE(quota_mt_reg));
}

static void __exit quota_mt_exit(void)
{
	xt_unregister_matches(quota_mt_reg, ARRAY_SIZE(quota_mt_reg));
}

module_init(quota_mt_init);
module_exit(quota_mt_exit);
