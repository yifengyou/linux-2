/*
 * AppArmor security module
 *
 * This file contains AppArmor network mediation
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2010 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include "include/apparmor.h"
#include "include/audit.h"
#include "include/context.h"
#include "include/net.h"
#include "include/policy.h"

#include "af_names.h"

static const char *sock_type_names[] = {
	"unknown(0)",
	"stream",
	"dgram",
	"raw",
	"rdm",
	"seqpacket",
	"dccp",
	"unknown(7)",
	"unknown(8)",
	"unknown(9)",
	"packet",
};

struct aa_audit_net {
	struct aa_audit base;

	int family, type, protocol;

};

/* audit callback for net specific fields */
static void audit_cb(struct audit_buffer *ab, struct aa_audit *va)
{
	struct aa_audit_net *sa = container_of(va, struct aa_audit_net, base);

	if (sa->family || sa->type) {
		if (address_family_names[sa->family]) {
			audit_log_format(ab, " family=");
			audit_log_string(ab, address_family_names[sa->family]);
		} else {
			audit_log_format(ab, " family=\"unknown(%d)\"",
					 sa->family);
		}
		if (sock_type_names[sa->type]) {
			audit_log_format(ab, " sock_type=");
			audit_log_string(ab, sock_type_names[sa->type]);
		} else {
			audit_log_format(ab, " sock_type=\"unknown(%d)\"",
					 sa->type);
		}
		audit_log_format(ab, " protocol=%d", sa->protocol);
	}

}

/**
 * aa_audit_net - audit network access
 * @profile: profile being enforced  (NOT NULL)
 * @sa: audit data  (NOT NULL)
 *
 * Returns: %0 or sa->error else other errorcode on failure
 */
static int aa_audit_net(struct aa_profile *profile, struct aa_audit_net *sa)
{
	int type = AUDIT_APPARMOR_AUTO;

	if (likely(!sa->base.error)) {
		u16 audit_mask = profile->net.audit[sa->family];
		if (likely((AUDIT_MODE(profile) != AUDIT_ALL) &&
			   !(1 << sa->type & audit_mask)))
			return 0;
		type = AUDIT_APPARMOR_AUDIT;
	} else {
		u16 quiet_mask = profile->net.quiet[sa->family];
		u16 kill_mask = 0;
		u16 denied = (1 << sa->type);

		if (denied & kill_mask)
			type = AUDIT_APPARMOR_KILL;

		if ((denied & quiet_mask) &&
		    AUDIT_MODE(profile) != AUDIT_NOQUIET &&
		    AUDIT_MODE(profile) != AUDIT_ALL)
			return COMPLAIN_MODE(profile) ? 0 : sa->base.error;
	}

	return aa_audit(type, profile, &sa->base, audit_cb);
}

/**
 * aa_net_perm - very course network access check
 * @profile: profile being enforced  (NOT NULL)
 * @operation: name of the operation being checked  (NOT NULL)
 * @family: network family
 * @type:   network type
 * @protocol: network protocol
 *
 * Returns: %0 else error if permission denied
 */
int aa_net_perm(struct aa_profile *profile, char *operation,
		int family, int type, int protocol)
{
	u16 family_mask;
	struct aa_audit_net sa = {
		.base.operation = operation,
		.base.gfp_mask = GFP_KERNEL,
		.family = family,
		.type = type,
		.protocol = protocol,
	};

	if ((family < 0) || (family >= AF_MAX))
		return -EINVAL;

	if ((type < 0) || (type >= SOCK_MAX))
		return -EINVAL;

	/* unix domain and netlink sockets are handled by ipc */
	if (family == AF_UNIX || family == AF_NETLINK)
		return 0;

	family_mask = profile->net.allowed[family];

	sa.base.error = (family_mask & (1 << type)) ? 0 : -EACCES;

	return aa_audit_net(profile, &sa);
}

/**
 * aa_revalidate_sk - Revalidate access to a sock
 * @sk: sock being revalidated  (NOT NULL)
 * @operation: name of operation being checked  (NOT NULL)
 *
 * Returns: %0 else error if permission denied
 */
int aa_revalidate_sk(struct sock *sk, char *operation)
{
	struct aa_profile *profile;
	int error = 0;

	/* aa_revalidate_sk should not be called from interrupt context
	 * don't mediate these calls as they are not task related
	 */
	if (in_interrupt())
		return 0;

	profile = __aa_current_profile();
	if (!unconfined(profile))
		error = aa_net_perm(profile, operation,
				    sk->sk_family, sk->sk_type,
				    sk->sk_protocol);

	return error;
}
