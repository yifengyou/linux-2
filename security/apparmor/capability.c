/*
 * AppArmor security module
 *
 * This file contains AppArmor capability mediation functions
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2010 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/gfp.h>

#include "include/apparmor.h"
#include "include/capability.h"
#include "include/context.h"
#include "include/policy.h"
#include "include/audit.h"

/*
 * Table of capability names: we generate it from capabilities.h.
 */
#include "capability_names.h"

struct audit_cache {
	struct aa_profile *profile;
	kernel_cap_t caps;
};

static DEFINE_PER_CPU(struct audit_cache, audit_cache);

struct aa_audit_caps {
	struct aa_audit base;

	int cap;
};

/**
 * audit_cb - call back for capability components of audit struct
 * @ab - audit buffer   (NOT NULL)
 * @va - audit struct to audit data from  (NOT NULL)
 */
static void audit_cb(struct audit_buffer *ab, struct aa_audit *va)
{
	struct aa_audit_caps *sa = container_of(va, struct aa_audit_caps, base);

	audit_log_format(ab, " name=");
	audit_log_untrustedstring(ab, capability_names[sa->cap]);
}

/**
 * aa_audit_caps - audit a capability
 * @profile: profile confining task
 * @sa: audit structure containing data to audit
 *
 * Do auditing of capability and handle, audit/complain/kill modes switching
 * and duplicate message elimination.
 *
 * returns: 0 or sa->error on succes,  error code on failure
 */
static int aa_audit_caps(struct aa_profile *profile, struct aa_audit_caps *sa)
{
	struct audit_cache *ent;
	int type = AUDIT_APPARMOR_AUTO;

	if (likely(!sa->base.error)) {
		/* test if auditing is being forced */
		if (likely((AUDIT_MODE(profile) != AUDIT_ALL) &&
			   !cap_raised(profile->caps.audit, sa->cap)))
			return 0;
		type = AUDIT_APPARMOR_AUDIT;
	} else if (DO_KILL(profile) ||
		   cap_raised(profile->caps.kill, sa->cap)) {
		type = AUDIT_APPARMOR_KILL;
	} else if (cap_raised(profile->caps.quiet, sa->cap) &&
		   AUDIT_MODE(profile) != AUDIT_NOQUIET &&
		   AUDIT_MODE(profile) != AUDIT_ALL) {
		/* quiet auditing */
		return sa->base.error;
	}

	/* Do simple duplicate message elimination */
	ent = &get_cpu_var(audit_cache);
	if (profile == ent->profile && cap_raised(ent->caps, sa->cap)) {
		put_cpu_var(audit_cache);
		if (COMPLAIN_MODE(profile))
			return 0;
		return sa->base.error;
	} else {
		aa_put_profile(ent->profile);
		ent->profile = aa_get_profile(profile);
		cap_raise(ent->caps, sa->cap);
	}
	put_cpu_var(audit_cache);

	return aa_audit(type, profile, &sa->base, audit_cb);
}

/**
 * aa_profile_capable - test if profile allows use of capability @cap
 * @profile: profile being enforced    (NOT NULL, NOT unconfined)
 * @cap: capability to test if allowed
 *
 * Returns: 0 if allowed else -EPERM
 */
static int aa_profile_capable(struct aa_profile *profile, int cap)
{
	return cap_raised(profile->caps.allowed, cap) ? 0 : -EPERM;
}

/**
 * aa_capable - test permission to use capability
 * @task: task doing capability test against
 * @profile: profile confining @task
 * @cap: capability to be tested
 * @audit: whether an audit record should be generated
 *
 * Look up capability in profile capability set.
 *
 * Returns: 0 on success, or else an error code.
 */
int aa_capable(struct task_struct *task, struct aa_profile *profile, int cap,
	       int audit)
{
	int error = aa_profile_capable(profile, cap);
	struct aa_audit_caps sa = {
		.base.operation = "capable",
		.base.task = task,
		.base.gfp_mask = GFP_ATOMIC,
		.base.error = error,
		.cap = cap,
	};

	if (!audit) {
		if (COMPLAIN_MODE(profile))
			return 0;
		return error;
	}

	return aa_audit_caps(profile, &sa);
}
