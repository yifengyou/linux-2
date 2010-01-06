/*
 * AppArmor security module
 *
 * This file contains AppArmor contexts used to associate "labels" to objects.
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2010 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#ifndef __AA_CONTEXT_H
#define __AA_CONTEXT_H

#include <linux/cred.h>
#include <linux/slab.h>
#include <linux/sched.h>

#include "policy.h"

/* struct aa_file_cxt - the AppArmor context the file was opened in
 * @profile: the profile the file was opened under
 * @perms: the permission the file was opened with
 */
struct aa_file_cxt {
	struct aa_profile *profile;
	u16 allowed;
};

static inline struct aa_file_cxt *aa_alloc_file_context(gfp_t gfp)
{
	return kzalloc(sizeof(struct aa_file_cxt), gfp);
}

static inline void aa_free_file_context(struct aa_file_cxt *cxt)
{
	aa_put_profile(cxt->profile);
	kzfree(cxt);
}

/* struct aa_task_cxt_group - a grouping label data for confined tasks
 * @profile: the current profile
 * @exec: profile to transition to on next exec
 * @previous: profile the task may return to
 * @token: magic value the task must know for returning to @previous_profile
 *
 * Contains the task's current profile (which could change due to
 * change_hat).  Plus the hat_magic needed during change_hat.
 */
struct aa_task_cxt_group {
	struct aa_profile *profile;
	struct aa_profile *onexec;
	struct aa_profile *previous;
	u64 token;
};

/**
 * struct aa_task_context - primary label for confined tasks
 * @sys: the system labeling for the task
 *
 * A task is confined by the intersection of its system and user profiles
 */
struct aa_task_context {
	struct aa_task_cxt_group sys;
};

struct aa_task_context *aa_alloc_task_context(gfp_t flags);
void aa_free_task_context(struct aa_task_context *cxt);
void aa_dup_task_context(struct aa_task_context *new,
			 const struct aa_task_context *old);
struct cred *aa_get_task_cred(const struct task_struct *task,
				struct aa_profile **sys);
int aa_replace_current_profiles(struct aa_profile *sys);
int aa_set_current_onexec(struct aa_profile *sys);
int aa_set_current_hat(struct aa_profile *profile, u64 token);
int aa_restore_previous_profile(u64 cookie);

/**
 * __aa_task_is_confined - determine if @task has any confinement
 * @task: task to check confinement of
 *
 * If @task != current needs to be called in RCU safe critical section
 */
static inline bool __aa_task_is_confined(struct task_struct *task)
{
	struct aa_task_context *cxt = __task_cred(task)->security;

	BUG_ON(!cxt);
	if (!aa_confined(cxt->sys.profile))
		return 0;

	return 1;
}

/**
 * aa_cred_policy - obtain cred's profiles
 * @cred: cred to obtain profiles from
 *
 * Returns: system confining profile
 *
 * does NOT increment reference count
 */
static inline struct aa_profile *aa_cred_policy(const struct cred *cred)
{
	struct aa_task_context *cxt = cred->security;
	BUG_ON(!cxt);
	return aa_confining_profile(cxt->sys.profile);
}

/**
 * __aa_current_profile - find the current tasks confining profile
 *
 * Returns: up to date confining profile or NULL if task is unconfined
 *
 * This fn will not update the tasks cred to the most up to date version
 * of the profile so it is safe to call when inside of locks.
 */
static inline struct aa_profile *__aa_current_profile(void)
{
	return aa_cred_policy(current_cred());
}

/**
 * aa_current_profile - find the current tasks confining profile and do updates
 *
 * Returns: up to date confinging profile or NULL if task is unconfined
 *
 * This fn will update the tasks cred structure if the profile has been
 * replaced.  Not safe to call inside locks
 */
static inline struct aa_profile *aa_current_profile(void)
{
	const struct aa_task_context *cxt = current_cred()->security;
	struct aa_profile *profile;
	BUG_ON(!cxt);

	profile = aa_profile_newest(cxt->sys.profile);
	/*
	 * Whether or not replacement succeeds, use newest profile so
	 * there is no need to update it after replacement.
	 */
	if (unlikely((cxt->sys.profile != profile)))
		aa_replace_current_profiles(profile);
	profile = aa_filter_profile(profile);

	return profile;
}

#endif /* __AA_CONTEXT_H */
