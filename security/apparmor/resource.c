/*
 * AppArmor security module
 *
 * This file contains AppArmor resource mediation and attachment
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2010 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include <linux/audit.h>

#include "include/audit.h"
#include "include/resource.h"
#include "include/policy.h"

struct aa_audit_resource {
	struct aa_audit base;

	int rlimit;
};

/* audit callback for resource specific fields */
static void audit_cb(struct audit_buffer *ab, struct aa_audit *va)
{
	struct aa_audit_resource *sa = container_of(va,
						    struct aa_audit_resource,
						    base);

	if (sa->rlimit)
		audit_log_format(ab, " rlimit=%d", sa->rlimit - 1);
}

/**
 * aa_audit_resource - audit setting resource limit
 * @profile: profile being enforced  (NOT NULL)
 * @sa: audit data  (NOT NULL)
 *
 * Returns: 0 or sa->error else other error code on failure
 */
static int aa_audit_resource(struct aa_profile *profile,
			     struct aa_audit_resource *sa)
{
	return aa_audit(AUDIT_APPARMOR_AUTO, profile, &sa->base, audit_cb);
}

/**
 * aa_task_setrlimit - test permission to set an rlimit
 * @profile - profile confining the task  (NOT NULL)
 * @resource - the resource being set
 * @new_rlim - the new resource limit  (NOT NULL)
 *
 * Control raising the processes hard limit.
 *
 * Returns: 0 or error code if setting resource failed
 */
int aa_task_setrlimit(struct aa_profile *profile, unsigned int resource,
		      struct rlimit *new_rlim)
{
	struct aa_audit_resource sa = {
		.base.operation = "setrlimit",
		.base.gfp_mask = GFP_KERNEL,
		.rlimit = resource + 1,
	};
	int error = 0;

	if (profile->rlimits.mask & (1 << resource) &&
	    new_rlim->rlim_max > profile->rlimits.limits[resource].rlim_max) {
		sa.base.error = -EACCES;

		error = aa_audit_resource(profile, &sa);
	}

	return error;
}

/**
 * __aa_transition_rlimits - apply new profile rlimits
 * @old: old profile on task  (MAYBE NULL)
 * @new: new profile with rlimits to apply  (NOT NULL)
 */
void __aa_transition_rlimits(struct aa_profile *old, struct aa_profile *new)
{
	unsigned int mask = 0;
	struct rlimit *rlim, *initrlim;
	int i;

	/* for any rlimits the profile controlled reset the soft limit
	 * to the less of the tasks hard limit and the init tasks soft limit
	 */
	if (old && old->rlimits.mask) {
		for (i = 0, mask = 1; i < RLIM_NLIMITS; i++, mask <<= 1) {
			if (old->rlimits.mask & mask) {
				rlim = current->signal->rlim + i;
				initrlim = init_task.signal->rlim + i;
				rlim->rlim_cur = min(rlim->rlim_max,
						     initrlim->rlim_cur);
			}
		}
	}

	/* set any new hard limits as dictated by the new profile */
	if (!(new && new->rlimits.mask))
		return;
	for (i = 0, mask = 1; i < RLIM_NLIMITS; i++, mask <<= 1) {
		if (!(new->rlimits.mask & mask))
			continue;

		rlim = current->signal->rlim + i;
		rlim->rlim_max = min(rlim->rlim_max,
				     new->rlimits.limits[i].rlim_max);
		/* soft limit should not exceed hard limit */
		rlim->rlim_cur = min(rlim->rlim_cur, rlim->rlim_max);
	}
}
