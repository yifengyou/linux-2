/*
 * AppArmor security module
 *
 * This file contains AppArmor functions used to manipulate object security
 * contexts.
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2010 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include "include/context.h"
#include "include/policy.h"

struct aa_task_cxt *aa_alloc_task_context(gfp_t flags)
{
	return kzalloc(sizeof(struct aa_task_cxt), flags);
}

void aa_free_task_context(struct aa_task_cxt *cxt)
{
	if (cxt) {
		aa_put_profile(cxt->profile);
		aa_put_profile(cxt->previous);
		aa_put_profile(cxt->onexec);

		kzfree(cxt);
	}
}

/**
 * aa_dup_task_context - duplicate a task context, incrementing reference counts
 * @new: a blank task context
 * @old: the task context to copy
 */
void aa_dup_task_context(struct aa_task_cxt *new, const struct aa_task_cxt *old)
{
	*new = *old;
	aa_get_profile(new->profile);
	aa_get_profile(new->previous);
	aa_get_profile(new->onexec);
}

/**
 * replace_cxt - replace a context profile
 * @cxt: task context
 * @profile: profile to replace cxt group
 *
 * Replace context grouping profile reference with @profile
 */
static void replace_group(struct aa_task_cxt *cxt, struct aa_profile *profile)
{
	if (cxt->profile == profile)
		return;

	BUG_ON(!profile);
	if (unconfined(profile) || (cxt->profile->ns != profile->ns)) {
		/* if switching to unconfined or a different profile namespace
		 * clear out context state
		 */
		aa_put_profile(cxt->previous);
		aa_put_profile(cxt->onexec);
		cxt->previous = NULL;
		cxt->onexec = NULL;
		cxt->token = 0;
	}
	aa_put_profile(cxt->profile);
	cxt->profile = aa_get_profile(profile);
}

/**
 * aa_replace_current_profiles - replace the current tasks profiles
 * @sys: new system profile
 *
 * Returns: error on failure
 */
int aa_replace_current_profiles(struct aa_profile *sys)
{
	struct aa_task_cxt *cxt;
	struct cred *new = prepare_creds();
	if (!new)
		return -ENOMEM;

	cxt = new->security;
	replace_group(cxt, sys);
	/* todo add user group */

	commit_creds(new);
	return 0;
}

/**
 * aa_set_current_onexec - set the tasks change_profile to happen onexec
 * @sys: system profile to set at exec
 *
 * Returns: error on failure
 */
int aa_set_current_onexec(struct aa_profile *sys)
{
	struct aa_task_cxt *cxt;
	struct cred *new = prepare_creds();
	if (!new)
		return -ENOMEM;

	cxt = new->security;
	aa_put_profile(cxt->onexec);
	cxt->onexec = aa_get_profile(sys);

	commit_creds(new);
	return 0;
}

/**
 * aa_set_current_hat - set the current tasks hat
 * @profile: profile to set as the current hat
 * @token: token value that must be specified to change from the hat
 *
 * Do switch of tasks hat.  If the task is currently in a hat
 * validate the token to match.
 *
 * Returns: error on failure
 */
int aa_set_current_hat(struct aa_profile *profile, u64 token)
{
	struct aa_task_cxt *cxt;
	struct cred *new = prepare_creds();
	if (!new)
		return -ENOMEM;

	cxt = new->security;
	if (!cxt->previous) {
		cxt->previous = cxt->profile;
		cxt->token = token;
	} else if (cxt->token == token) {
		aa_put_profile(cxt->profile);
	} else {
		/* previous_profile && cxt->token != token */
		abort_creds(new);
		return -EACCES;
	}
	cxt->profile = aa_get_profile(aa_newest_version(profile));
	/* clear exec on switching context */
	aa_put_profile(cxt->onexec);
	cxt->onexec = NULL;

	commit_creds(new);
	return 0;
}

/**
 * aa_restore_previous_profile - exit from hat context restoring the profile
 * @token: the token that must be matched to exit hat context
 *
 * Attempt to return out of a hat to the previous profile.  The token
 * must match the stored token value.
 *
 * Returns: error of failure
 */
int aa_restore_previous_profile(u64 token)
{
	struct aa_task_cxt *cxt;
	struct cred *new = prepare_creds();
	if (!new)
		return -ENOMEM;

	cxt = new->security;
	if (cxt->token != token) {
		abort_creds(new);
		return -EACCES;
	}
	/* ignore restores when there is no saved profile */
	if (!cxt->previous) {
		abort_creds(new);
		return 0;
	}

	aa_put_profile(cxt->profile);
	cxt->profile = aa_newest_version(cxt->previous);
	if (unlikely(cxt->profile != cxt->previous)) {
		aa_get_profile(cxt->profile);
		aa_put_profile(cxt->previous);
	}
	/* clear exec && prev information when restoring to previous context */
	cxt->previous = NULL;
	cxt->token = 0;
	aa_put_profile(cxt->onexec);
	cxt->onexec = NULL;

	commit_creds(new);
	return 0;
}
