/*
 * AppArmor security module
 *
 * This file contains AppArmor policy attachment and domain transitions
 *
 * Copyright (C) 2002-2008 Novell/SUSE
 * Copyright 2009-2010 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include <linux/errno.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/syscalls.h>
#include <linux/tracehook.h>
#include <linux/personality.h>

#include "include/audit.h"
#include "include/apparmorfs.h"
#include "include/context.h"
#include "include/domain.h"
#include "include/file.h"
#include "include/ipc.h"
#include "include/match.h"
#include "include/path.h"
#include "include/policy.h"

/**
 * aa_free_domain_entries - free entries in a domain table
 * @domain: the domain table to free
 */
void aa_free_domain_entries(struct aa_domain *domain)
{
	int i;

	if (!domain->table)
		return;

	for (i = 0; i < domain->size; i++)
		kzfree(domain->table[i]);
	kzfree(domain->table);
	domain->table = NULL;
}

/*
 * check if the task is ptraced and if so if the tracing task is allowed
 * to trace the new domain
 */
static int aa_may_change_ptraced_domain(struct task_struct *task,
					struct aa_profile *to_profile)
{
	struct task_struct *tracer;
	struct cred *cred = NULL;
	struct aa_profile *tracerp = NULL;
	int error = 0;

	rcu_read_lock();
	tracer = tracehook_tracer_task(task);
	if (tracer)
		/* released below */
		cred = aa_get_task_cred(tracer, &tracerp);
	rcu_read_unlock();

	/* not ptraced */
	if (!tracer || !tracerp)
		goto out;

	error = aa_may_ptrace(tracer, tracerp, to_profile, PTRACE_MODE_ATTACH);

out:
	if (cred)
		put_cred(cred);

	return error;
}

/**
 * change_profile_perms - find permissions for change_profile
 * @profile: the current profile
 * @ns: the namespace being switched to
 * @name: the name of the profile to change to
 * @rstate: if !NULL will contain the state the match finished in
 */
static struct file_perms change_profile_perms(struct aa_profile *profile,
					      struct aa_namespace *ns,
					      const char *name,
					      unsigned int *rstate)
{
	struct file_perms perms;
	struct path_cond cond = { };
	unsigned int state;

	if (!profile) {
		/* unconfined */
		perms.allowed = AA_MAY_CHANGE_PROFILE;
		perms.xindex = perms.dindex = 0;
		perms.audit = perms.quiet = perms.kill = 0;
		if (rstate)
			*rstate = 0;
		return perms;
	} else if (!profile->file.dfa) {
		return nullperms;
	} else if ((ns == profile->ns)) {
		/* try matching against rules with out namespace prependend */
		perms = aa_str_perms(profile->file.dfa, DFA_START, name, &cond,
				     rstate);
		if (COMBINED_PERM_MASK(perms) & AA_MAY_CHANGE_PROFILE)
			return perms;
	}

	/* try matching with namespace name and then profile */
	state = aa_dfa_match(profile->file.dfa, DFA_START, ns->base.name);
	state = aa_dfa_null_transition(profile->file.dfa, state, 0);
	return aa_str_perms(profile->file.dfa, state, name, &cond, rstate);
}

/* __aa_attach_match_ - find an attachment match
 * @name - to match against
 * @head - profile list to walk
 *
 * Do a linear search on the profiles in the list.  There is a matching
 * preference where an exact match is prefered over a name which uses
 * expressions to match, and matching expressions with the greatest
 * xmatch_len are prefered.
 */
static struct aa_profile *__aa_attach_match(const char *name,
					    struct list_head *head)
{
	int len = 0;
	struct aa_profile *profile, *candidate = NULL;

	list_for_each_entry(profile, head, base.list) {
		if (profile->flags & PFLAG_NULL)
			continue;
		if (profile->xmatch && profile->xmatch_len > len) {
			unsigned int state = aa_dfa_match(profile->xmatch,
							  DFA_START, name);
			u16 perm = dfa_user_allow(profile->xmatch, state);
			/* any accepting state means a valid match. */
			if (perm & MAY_EXEC) {
				candidate = profile;
				len = profile->xmatch_len;
			}
		} else if (!strcmp(profile->base.name, name))
			/* exact non-re match, no more searching required */
			return profile;
	}

	return candidate;
}

/**
 * aa_sys_find_attach - do attachment search for sys unconfined processes
 * @base: the base to search
 * name: the executable name to match against
 */
static struct aa_profile *aa_sys_find_attach(struct aa_policy_common *base,
					     const char *name)
{
	struct aa_profile *profile;

	read_lock(&base->lock);
	profile = aa_get_profile(__aa_attach_match(name, &base->profiles));
	read_unlock(&base->lock);

	return profile;
}

/**
 * separate_fqname - separate the namespace and profile names
 * @fqname: the fqname name to split
 * @ns_name: the namespace name if it exists
 *
 * Returns: profile name if it is specified
 *
 * This is the xtable equivalent routine of aa_split_fqname.  It finds the
 * split in an xtable fqname which contains an embedded \0 instead of a :
 * if a namespace is specified.  This is done so the xtable is constant and
 * isn't resplit on every lookup.
 *
 * Either the profile or namespace name may be optional but if the namespace
 * is specified the profile name termination must be present.  This results
 * in the following possible encodings:
 * profile_name\0
 * :ns_name\0profile_name\0
 * :ns_name\0\0
 */
static const char *separate_fqname(const char *fqname, const char **ns_name)
{
	const char *name;

	if (fqname[0] == ':') {
		*ns_name = fqname + 1;		/* skip : */
		name = *ns_name + strlen(*ns_name) + 1;
		if (!*name)
			name = NULL;
	} else {
		*ns_name = NULL;
		name = fqname;
	}

	return name;
}

static const char *next_name(int xtype, const char *name)
{
	return NULL;
}

/**
 * x_to_profile - get target profile for a given xindex
 * @ns: namespace of profile
 * @profile: current profile
 * @name: to to lookup if specified
 * @xindex: index into x transition table
 *
 * find profile for a transition index
 *
 * Returns: refcounted profile or NULL if not found available
 */
static struct aa_profile *x_to_profile(struct aa_namespace *ns,
				       struct aa_profile *profile,
				       const char *name, u16 xindex)
{
	struct aa_profile *new_profile = NULL;
	u16 xtype = xindex & AA_X_TYPE_MASK;
	int index = xindex & AA_X_INDEX_MASK;

	if (!profile)
		profile = ns->unconfined;

	switch (xtype) {
	case AA_X_NONE:
		/* fail exec unless ix || ux fallback - handled by caller */
		return NULL;
	case AA_X_NAME:
		if (xindex & AA_X_CHILD)
			/* released by caller */
			new_profile = aa_sys_find_attach(&profile->base, name);
		else
			/* released by caller */
			new_profile = aa_sys_find_attach(&ns->base, name);

		goto out;
	case AA_X_TABLE:
		/* index is guarenteed to be in range */
		name = profile->file.trans.table[index];
		break;
	}

	for (; !new_profile && name; name = next_name(xtype, name)) {
		struct aa_namespace *new_ns;
		const char *xname = NULL;

		new_ns = NULL;
		if (xindex & AA_X_CHILD) {
			/* release by caller */
			new_profile = aa_find_child(profile, name);
			if (new_profile)
				return new_profile;
			continue;
		} else if (*name == ':') {
			/* switching namespace */
			const char *ns_name;
			xname = name = separate_fqname(name, &ns_name);
			if (!xname)
				/* no name so use profile name */
				xname = profile->base.hname;
			if (*ns_name == '@') {
				/* TODO: variable support */
				;
			}
			/* released below */
			new_ns = aa_find_namespace(ns_name);
			if (!new_ns)
				continue;
		} else if (*name == '@') {
			/* TODO: variable support */
			continue;
		} else {
			xname = name;
		}

		/* released by caller */
		new_profile = aa_find_profile(new_ns ? new_ns : ns, xname);
		aa_put_namespace(new_ns);
	}

out:
	/* released by caller */
	return new_profile;
}

/**
 * apparmor_bprm_set_creds - set the new creds on the bprm struct
 * @bprm: binprm for the exec
 *
 * Returns: error on failure
 */
int apparmor_bprm_set_creds(struct linux_binprm *bprm)
{
	struct aa_task_context *cxt;
	struct aa_profile *profile, *new_profile = NULL;
	struct aa_namespace *ns;
	char *buffer = NULL;
	unsigned int state = DFA_START;
	struct path_cond cond = {
		bprm->file->f_path.dentry->d_inode->i_uid,
		bprm->file->f_path.dentry->d_inode->i_mode
	};
	struct aa_audit_file sa = {
		.base.operation = "exec",
		.base.gfp_mask = GFP_KERNEL,
		.request = MAY_EXEC,
		.cond = &cond,
	};

	sa.base.error = cap_bprm_set_creds(bprm);
	if (sa.base.error)
		return sa.base.error;

	if (bprm->cred_prepared)
		return 0;

	cxt = bprm->cred->security;
	BUG_ON(!cxt);

	profile = aa_profile_newest(cxt->sys.profile);
	/*
	 * get the namespace from the replacement profile as replacement
	 * can change the namespace
	 */
	ns = profile->ns;
	/* filter after namespace assignment */
	profile = aa_filter_profile(profile);

	/* buffer freed below, name is pointer inside of buffer */
	sa.base.error = aa_get_name(&bprm->file->f_path, 0, &buffer,
				    (char **)&sa.name);
	if (sa.base.error) {
		if (!profile || profile->flags & PFLAG_IX_ON_NAME_ERROR)
			sa.base.error = 0;
		sa.base.info = "Exec failed name resolution";
		sa.name = bprm->filename;
		goto audit;
	}

	if (!profile) {
		/* unconfined task - attach profile if one matches */
		new_profile = aa_sys_find_attach(&ns->base, sa.name);
		if (!new_profile)
			goto cleanup;
		goto apply;
	} else if (cxt->sys.onexec) {
		/*
		 * onexec permissions are stored in a pair, rewalk the
		 * dfa to get start of the exec path match.
		 */
		sa.perms = change_profile_perms(profile, cxt->sys.onexec->ns,
						sa.name, &state);
		state = aa_dfa_null_transition(profile->file.dfa, state, 0);
	}
	sa.perms = aa_str_perms(profile->file.dfa, state, sa.name, &cond, NULL);
	if (cxt->sys.onexec && sa.perms.allowed & AA_MAY_ONEXEC) {
		new_profile = cxt->sys.onexec;
		cxt->sys.onexec = NULL;
		sa.base.info = "change_profile onexec";
	} else if (sa.perms.allowed & MAY_EXEC) {
		new_profile = x_to_profile(ns, profile, sa.name,
					   sa.perms.xindex);
		if (!new_profile) {
			if (sa.perms.xindex & AA_X_INHERIT) {
				/* (p|c|n)ix - don't change profile */
				sa.base.info = "ix fallback";
				goto x_clear;
			} else if (sa.perms.xindex & AA_X_UNCONFINED) {
				new_profile = aa_get_profile(ns->unconfined);
				sa.base.info = "ux fallback";
			} else {
				sa.base.error = -ENOENT;
				sa.base.info = "profile not found";
			}
		}
	} else if (PROFILE_COMPLAIN(profile)) {
		new_profile = aa_new_null_profile(profile, 0);
		sa.base.error = -EACCES;
		if (!new_profile) {
			sa.base.error = -ENOMEM;
			sa.base.info = "could not create null profile";
		} else
			sa.name2 = new_profile->base.hname;
		sa.perms.xindex |= AA_X_UNSAFE;
	} else {
		sa.base.error = -EACCES;
	}

	if (!new_profile)
		goto audit;

	if (profile == new_profile) {
		aa_put_profile(new_profile);
		goto audit;
	}

	if (bprm->unsafe & LSM_UNSAFE_SHARE) {
		/* FIXME: currently don't mediate shared state */
		;
	}

	if (bprm->unsafe & (LSM_UNSAFE_PTRACE | LSM_UNSAFE_PTRACE_CAP)) {
		sa.base.error = aa_may_change_ptraced_domain(current,
							     new_profile);
		if (sa.base.error)
			goto audit;
	}

	/* Determine if secure exec is needed.
	 * Can be at this point for the following reasons:
	 * 1. unconfined switching to confined
	 * 2. confined switching to different confinement
	 * 3. confined switching to unconfined
	 *
	 * Cases 2 and 3 are marked as requiring secure exec
	 * (unless policy specified "unsafe exec")
	 *
	 * bprm->unsafe is used to cache the AA_X_UNSAFE permission
	 * to avoid having to recompute in secureexec
	 */
	if (!(sa.perms.xindex & AA_X_UNSAFE))
		bprm->unsafe |= AA_SECURE_X_NEEDED;

apply:
	sa.name2 = new_profile->base.hname;
	/* When switching namespace ensure its part of audit message */
	if (new_profile->ns != ns)
		sa.name3 = new_profile->ns->base.hname;

	/* when transitioning profiles clear unsafe personality bits */
	bprm->per_clear |= PER_CLEAR_ON_SETID;

	aa_put_profile(cxt->sys.profile);
	/* transfer new profile reference will be released when cxt is freed */
	cxt->sys.profile = new_profile;

x_clear:
	aa_put_profile(cxt->sys.previous);
	aa_put_profile(cxt->sys.onexec);
	cxt->sys.previous = NULL;
	cxt->sys.onexec = NULL;
	cxt->sys.token = 0;

audit:
	sa.base.error = aa_audit_file(profile, &sa);

cleanup:
	kfree(buffer);

	return sa.base.error;
}

int apparmor_bprm_secureexec(struct linux_binprm *bprm)
{
	int ret = cap_bprm_secureexec(bprm);

	/* the decision to use secure exec is computed in set_creds
	 * and stored in bprm->unsafe.
	 */
	if (!ret && (bprm->unsafe & AA_SECURE_X_NEEDED))
		ret = 1;

	return ret;
}

void apparmor_bprm_committing_creds(struct linux_binprm *bprm)
{
	struct aa_profile *profile = __aa_current_profile();
	struct aa_task_context *new_cxt = bprm->cred->security;

	/* bail out if unconfined or not changing profile */
	if ((new_cxt->sys.profile == profile) ||
	    (!aa_confined(new_cxt->sys.profile)))
		return;

	current->pdeath_signal = 0;

	/* reset soft limits and set hard limits for the new profile */
	__aa_transition_rlimits(profile, new_cxt->sys.profile);
}

void apparmor_bprm_committed_creds(struct linux_binprm *bprm)
{
	/* TODO: cleanup signals - ipc mediation */
	return;
}

/*
 * Functions for self directed profile change
 */

static char *new_compound_name(const char *n1, const char *n2)
{
	char *name = kmalloc(strlen(n1) + strlen(n2) + 3, GFP_KERNEL);
	if (name)
		sprintf(name, "%s//%s", n1, n2);
	return name;
}

/**
 * aa_change_hat - change hat to/from subprofile
 * @hat_name: hat to change to
 * @token: magic value to validate the hat change
 * @permtest: true if this is just a permission test
 *
 * Change to new @hat_name, and store the @hat_magic in the current task
 * context.  If the new @hat_name is %NULL and the @token matches that
 * stored in the current task context and is not 0, return to the top level
 * profile.
 * Returns %0 on success, error otherwise.
 */
int aa_change_hat(const char *hat_name, u64 token, int permtest)
{
	const struct cred *cred;
	struct aa_task_context *cxt;
	struct aa_profile *profile, *previous_profile, *hat = NULL;
	struct aa_audit_file sa = {
		.base.gfp_mask = GFP_KERNEL,
		.base.operation = "change_hat",
		.request = AA_MAY_CHANGEHAT,
	};
	char *name = NULL;

	/* released below */
	cred = aa_get_task_cred(current, &profile);
	cxt = cred->security;
	previous_profile = cxt->sys.previous;

	if (!profile) {
		sa.base.info = "unconfined";
		sa.base.error = -EPERM;
		goto audit;
	}

	if (hat_name) {
		/* attempting to change into a new hat or switch to a sibling */
		struct aa_profile *root;
		root = PROFILE_IS_HAT(profile) ? profile->parent : profile;
		sa.name2 = profile->ns->base.hname;

		/* released below */
		hat = aa_find_child(root, hat_name);
		if (!hat) {
			if (list_empty(&root->base.profiles) ||
			    PROFILE_COMPLAIN(root))
				sa.base.error = -ENOENT;
			if (permtest || !PROFILE_COMPLAIN(root))
				/* probing is an expected unfortunate behavior
				 * of the change_hat api is traditionally quiet
				 */
				goto out;

			/* freed below */
			name = new_compound_name(root->base.hname, hat_name);

			sa.name = name;
			sa.base.info = "hat not found";
			/* released below */
			hat = aa_new_null_profile(profile, 1);
			if (!hat) {
				sa.base.info = "failed null profile create";
				sa.base.error = -ENOMEM;
				goto audit;
			}
		} else {
			sa.name = hat->base.hname;
			if (!PROFILE_IS_HAT(hat)) {
				sa.base.info = "target not hat";
				sa.base.error = -EPERM;
				goto audit;
			}
		}

		sa.base.error = aa_may_change_ptraced_domain(current, hat);
		if (sa.base.error) {
			sa.base.info = "ptraced";
			sa.base.error = -EPERM;
			goto audit;
		}

		if (!permtest) {
			sa.base.error = aa_set_current_hat(hat, token);
			if (sa.base.error == -EACCES)
				/* kill task incase of brute force attacks */
				sa.perms.kill = AA_MAY_CHANGEHAT;
			else if (name && !sa.base.error)
				/* reset error for learning of new hats */
				sa.base.error = -ENOENT;
		}
	} else if (previous_profile) {
		/* Return to saved profile.  Kill task if restore fails
		 * to avoid brute force attacks
		 */
		sa.name = previous_profile->base.hname;
		sa.base.error = aa_restore_previous_profile(token);
		sa.perms.kill = AA_MAY_CHANGEHAT;
	} else
		/* ignore restores when there is no saved profile */
		goto out;

audit:
	if (!permtest)
		sa.base.error = aa_audit_file(profile, &sa);

out:
	aa_put_profile(hat);
	kfree(name);
	put_cred(cred);

	return sa.base.error;
}

/**
 * aa_change_profile - perform a one-way profile transition
 * @ns_name: name of the profile namespace to change to
 * @hname: name of profile to change to
 * @onexec: whether this transition is to take place immediately or at exec
 * @permtest: true if this is just a permission test
 *
 * Change to new profile @name.  Unlike with hats, there is no way
 * to change back.  If @onexec then the transition is delayed until
 * the next exec.
 *
 * Returns %0 on success, error otherwise.
 */
int aa_change_profile(const char *ns_name, const char *hname, int onexec,
		      int permtest)
{
	const struct cred *cred;
	struct aa_task_context *cxt;
	struct aa_profile *profile, *target = NULL;
	struct aa_namespace *ns = NULL;
	struct aa_audit_file sa = {
		.request = AA_MAY_CHANGE_PROFILE,
		.base.gfp_mask = GFP_KERNEL,
	};

	if (!hname && !ns_name)
		return -EINVAL;

	if (onexec)
		sa.base.operation = "change_onexec";
	else
		sa.base.operation = "change_profile";

	cred = aa_get_task_cred(current, &profile);
	cxt = cred->security;

	if (ns_name) {
		/* released below */
		ns = aa_find_namespace(ns_name);
		if (!ns) {
			/* we don't create new namespace in complain mode */
			sa.name2 = ns_name;
			sa.base.info = "namespace not found";
			sa.base.error = -ENOENT;
			goto audit;
		}
		sa.name2 = ns->base.hname;
	} else {
		/* released below */
		ns = aa_get_namespace(cxt->sys.profile->ns);
		sa.name2 = ns->base.hname;
	}

	/* if the name was not specified, use the name of the current profile */
	if (!hname) {
		if (!profile)
			hname = ns->unconfined->base.hname;
		else
			hname = profile->base.hname;
	}
	sa.name = hname;

	sa.perms = change_profile_perms(profile, ns, hname, NULL);
	if (!(sa.perms.allowed & AA_MAY_CHANGE_PROFILE)) {
		sa.base.error = -EACCES;
		goto audit;
	}

	/* released below */
	target = aa_find_profile(ns, hname);
	if (!target) {
		sa.base.info = "profile not found";
		sa.base.error = -ENOENT;
		if (permtest || !PROFILE_COMPLAIN(profile))
			goto audit;
		/* release below */
		target = aa_new_null_profile(profile, 0);
		if (!target) {
			sa.base.info = "failed null profile create";
			sa.base.error = -ENOMEM;
			goto audit;
		}
	}

	/* check if tracing task is allowed to trace target domain */
	sa.base.error = aa_may_change_ptraced_domain(current, target);
	if (sa.base.error) {
		sa.base.info = "ptrace prevents transition";
		goto audit;
	}

	if (permtest)
		goto audit;

	if (onexec)
		sa.base.error = aa_set_current_onexec(target);
	else
		sa.base.error = aa_replace_current_profiles(target);

audit:
	if (!permtest)
		sa.base.error = aa_audit_file(profile, &sa);

	aa_put_namespace(ns);
	aa_put_profile(target);
	put_cred(cred);

	return sa.base.error;
}
