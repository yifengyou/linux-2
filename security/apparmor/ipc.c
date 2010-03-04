/*
 * AppArmor security module
 *
 * This file contains AppArmor ipc mediation
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2010 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include <linux/gfp.h>
#include <linux/ptrace.h>

#include "include/audit.h"
#include "include/capability.h"
#include "include/context.h"
#include "include/policy.h"

struct aa_audit_ptrace {
	struct aa_audit base;

	pid_t tracer, tracee;
};

/* call back to audit ptrace fields */
static void audit_cb(struct audit_buffer *ab, struct aa_audit *va)
{
	struct aa_audit_ptrace *sa = container_of(va, struct aa_audit_ptrace,
						  base);
	audit_log_format(ab, " tracer=%d tracee=%d", sa->tracer, sa->tracee);
}

/**
 * aa_audit_ptrace - do auditing for ptrace
 * @profile: profile being enforced  (NOT NULL)
 * @sa: audit structure  (NOT NULL)
 *
 * Returns: %0 or error code
 */
static int aa_audit_ptrace(struct aa_profile *profile,
			   struct aa_audit_ptrace *sa)
{
	return aa_audit(AUDIT_APPARMOR_AUTO, profile, &sa->base, audit_cb);
}

/**
 * aa_may_ptrace - test if tracer task can trace the tracee
 * @tracer_task: task who will do the tracing  (NOT NULL)
 * @tracer: profile of the task doing the tracing  (NOT NULL)
 * @tracee: task to be traced
 * @mode: whether PTRACE_MODE_READ || PTRACE_MODE_ATTACH
 *
 * Returns: %0 else error code if permission denied or error
 */
int aa_may_ptrace(struct task_struct *tracer_task, struct aa_profile *tracer,
		  struct aa_profile *tracee, unsigned int mode)
{
	/* TODO: currently only based on capability, not extended ptrace
	 *       rules,
	 *       Test mode for PTRACE_MODE_READ || PTRACE_MODE_ATTACH
	 */

	if (!tracer || tracer == tracee)
		return 0;
	/* log this capability request */
	return aa_capable(tracer_task, tracer, CAP_SYS_PTRACE, 1);
}

/**
 * aa_ptrace - do ptrace permission check and auditing
 * @tracer: task doing the tracing
 * @tracee: task being traced
 * @mode: ptrace mode either PTRACE_MODE_READ || PTRACE_MODE_ATTACH
 *
 * Returns: %0 else error code if permission denied or error
 */
int aa_ptrace(struct task_struct *tracer, struct task_struct *tracee,
	      unsigned int mode)
{
	/*
	 * tracer can ptrace tracee when
	 * - tracer is unconfined ||
	 * - tracer & tracee are in the same namespace &&
	 *   - tracer is in complain mode
	 *   - tracer has rules allowing it to trace tracee currently this is:
	 *       - confined by the same profile ||
	 *       - tracer profile has CAP_SYS_PTRACE
	 */

	struct aa_profile *tracer_p;
	/* cred released below */
	const struct cred *cred = get_task_cred(tracer);
	int error = 0;
	tracer_p = aa_cred_profile(cred);

	if (!unconfined(tracer_p)) {
		struct aa_audit_ptrace sa = {
			.base.operation = "ptrace",
			.base.gfp_mask = GFP_ATOMIC,
			.tracer = tracer->pid,
			.tracee = tracee->pid,
		};
		/* FIXME: different namespace restriction can be lifted
		 * if, namespace are matched to AppArmor namespaces
		 */
		struct aa_profile *tracee_p;
		/* lcred released below */
		struct cred *lcred = get_task_cred(tracee);
		tracee_p = aa_cred_profile(lcred);

		sa.base.error = aa_may_ptrace(tracer, tracer_p, tracee_p, mode);
		sa.base.error = aa_audit_ptrace(tracer_p, &sa);

		put_cred(lcred);
		error = sa.base.error;
	}
	put_cred(cred);

	return error;
}
