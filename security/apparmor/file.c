/*
 * AppArmor security module
 *
 * This file contains AppArmor mediation of files
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
#include "include/file.h"
#include "include/match.h"
#include "include/path.h"
#include "include/policy.h"

struct file_perms nullperms;

/**
 * aa_audit_file_sub_mask - convert a permission mask into string
 * @buffer: buffer to write string to  (NOT NULL)
 * @mask: permission mask to convert
 * @xindex: xindex
 *
 * NOTE: caller must make sure buffer is large enough for @mask
 */
static void aa_audit_file_sub_mask(char *buffer, u16 mask, u16 xindex)
{
	char *m = buffer;

	if (mask & AA_EXEC_MMAP)
		*m++ = 'm';
	if (mask & MAY_READ)
		*m++ = 'r';
	if (mask & (MAY_WRITE | AA_MAY_CHMOD | AA_MAY_CHOWN))
		*m++ = 'w';
	else if (mask & MAY_APPEND)
		*m++ = 'a';
	if (mask & AA_MAY_CREATE)
		*m++ = 'c';
	if (mask & AA_MAY_DELETE)
		*m++ = 'd';
	if (mask & AA_MAY_LINK)
		*m++ = 'l';
	if (mask & AA_MAY_LOCK)
		*m++ = 'k';
	if (mask & MAY_EXEC)
		*m++ = 'x';
	*m++ = '\0';
}

/**
 * aa_audit_file_mask - convert mask to owner::other string
 * @buffer: buffer to write string to (NOT NULL)
 * @mask: permission mask to convert
 * @xindex: xindex
 * @owner: if the mask is for owner or other
 */
static void aa_audit_file_mask(struct audit_buffer *ab, u16 mask, int xindex,
			       int owner)
{
	char str[10];

	if (owner) {
		aa_audit_file_sub_mask(str, mask, xindex);
		strcat(str, "::");
	} else {
		strcpy(str, "::");
		aa_audit_file_sub_mask(str + 2, mask, xindex);
	}
	audit_log_string(ab, str);
}

/**
 * file_audit_cb - call back for file specific audit fields
 * @ab: audit_buffer  (NOT NULL)
 * @va: audit struct to audit values of  (NOT NULL)
 */
static void file_audit_cb(struct audit_buffer *ab, struct aa_audit *va)
{
	struct aa_audit_file *sa = container_of(va, struct aa_audit_file, base);
	u16 denied = sa->request & ~sa->perms.allowed;
	uid_t fsuid;

	fsuid = current_fsuid();

	if (sa->request & AA_AUDIT_FILE_MASK) {
		audit_log_format(ab, " requested_mask=");
		aa_audit_file_mask(ab, sa->request, AA_X_NONE,
				   fsuid == sa->cond->uid);
	}
	if (denied & AA_AUDIT_FILE_MASK) {
		audit_log_format(ab, " denied_mask=");
		aa_audit_file_mask(ab, denied, sa->perms.xindex,
				   fsuid == sa->cond->uid);
	}
	if (sa->request & AA_AUDIT_FILE_MASK) {
		audit_log_format(ab, " fsuid=%d", fsuid);
		audit_log_format(ab, " ouid=%d", sa->cond->uid);
	}

	if (sa->name) {
		audit_log_format(ab, " name=");
		audit_log_untrustedstring(ab, sa->name);
	}

	if (sa->name2) {
		audit_log_format(ab, " name2=");
		audit_log_untrustedstring(ab, sa->name2);
	}

	if (sa->name3) {
		audit_log_format(ab, " name3=");
		audit_log_untrustedstring(ab, sa->name3);
	}
}

/**
 * aa_audit_file - handle the auditing of file operations
 * @profile: the profile being enforced  (NOT NULL)
 * @sa: file auditing context  (NOT NULL)
 *
 * Returns: %0 or error on failure
 */
int aa_audit_file(struct aa_profile *profile, struct aa_audit_file *sa)
{
	int type = AUDIT_APPARMOR_AUTO;

	if (likely(!sa->base.error)) {
		u16 mask = sa->perms.audit;

		if (unlikely(AUDIT_MODE(profile) == AUDIT_ALL))
			mask = 0xffff;

		/* mask off perms that are not being force audited */
		sa->request &= mask;

		if (likely(!sa->request))
			return 0;
		type = AUDIT_APPARMOR_AUDIT;
	} else {
		/* only report permissions that were denied */
		sa->request = sa->request & ~sa->perms.allowed;

		if (sa->request & sa->perms.kill)
			type = AUDIT_APPARMOR_KILL;

		/* quiet known rejects, assumes quiet and kill do not overlap */
		if ((sa->request & sa->perms.quiet) &&
		    AUDIT_MODE(profile) != AUDIT_NOQUIET &&
		    AUDIT_MODE(profile) != AUDIT_ALL)
			sa->request &= ~sa->perms.quiet;

		if (!sa->request)
			return COMPLAIN_MODE(profile) ? 0 : sa->base.error;
	}
	return aa_audit(type, profile, &sa->base, file_audit_cb);
}

/**
 * aa_compute_perms - convert dfa compressed perms to internal perms
 * @dfa: dfa to compute perms for   (NOT NULL)
 * @state: state in dfa
 * @cond:  conditions to consider  (NOT NULL)
 *
 * TODO: convert from dfa + state to permission entry, do computation conversion
 *       at load time.
 *
 * Returns: computed permission set
 */
static struct file_perms aa_compute_perms(struct aa_dfa *dfa,
					  unsigned int state,
					  struct path_cond *cond)
{
	struct file_perms perms;

	/* FIXME: change over to new dfa format
	 * currently file perms are encoded in the dfa, new format
	 * splits the permissions from the dfa.  This mapping can be
	 * done at profile load
	 */
	perms.kill = 0;
	perms.dindex = 0;

	if (current_fsuid() == cond->uid) {
		perms.allowed = dfa_user_allow(dfa, state);
		perms.audit = dfa_user_audit(dfa, state);
		perms.quiet = dfa_user_quiet(dfa, state);
		perms.xindex = dfa_user_xindex(dfa, state);
	} else {
		perms.allowed = dfa_other_allow(dfa, state);
		perms.audit = dfa_other_audit(dfa, state);
		perms.quiet = dfa_other_quiet(dfa, state);
		perms.xindex = dfa_other_xindex(dfa, state);
	}
	/* in the old mapping MAY_WRITE implies
	 * AA_MAY_CREATE | AA_MAY_CHMOD | AA_MAY_CHOWN */
	if (perms.allowed & MAY_WRITE)
		perms.allowed |= AA_MAY_CREATE | AA_MAY_CHMOD | AA_MAY_CHOWN |
			AA_MAY_DELETE;
	if (perms.audit & MAY_WRITE)
		perms.audit |= AA_MAY_CREATE | AA_MAY_CHMOD | AA_MAY_CHOWN |
			AA_MAY_DELETE;
	if (perms.quiet & MAY_WRITE)
		perms.quiet |= AA_MAY_CREATE | AA_MAY_CHMOD | AA_MAY_CHOWN |
			AA_MAY_DELETE;

	/* in the old mapping AA_MAY_LOCK and link subset are overlayed
	 * and only determined by which part of a pair they are  in
	 */
	if (perms.allowed & AA_MAY_LOCK)
		perms.allowed |= AA_LINK_SUBSET;

	/* change_profile wasn't determined by ownership in old mapping */
	if (ACCEPT_TABLE(dfa)[state] & 0x80000000)
		perms.allowed |= AA_MAY_CHANGE_PROFILE;

	return perms;
}

/**
 * aa_str_perms - find permission that match @name
 * @dfa: to match against  (NOT NULL)
 * @state: state to start matching in
 * @name: string to match against dfa  (NOT NULL)
 * @cond: conditions to consider for permission set computation  (NOT NULL)
 * @rstate: if !NULL return state match finished in (MAYBE NULL)
 *
 * TODO: Update when permission mapping is moved to load time
 *
 * Returns: file permission for @name
 */
struct file_perms aa_str_perms(struct aa_dfa *dfa, unsigned int start,
			       const char *name, struct path_cond *cond,
			       unsigned int *rstate)
{
	unsigned int state;
	if (!dfa)
		return nullperms;

	state = aa_dfa_match(dfa, start, name);

	if (rstate)
		*rstate = state;

	/* TODO: convert to new dfa format */

	return aa_compute_perms(dfa, state, cond);
}

/**
 * aa_pathstr_perm - do permission check & audit for @name
 * @profile: profile being enforced  (NOT NULL)
 * @op: name of the operation  (NOT NULL)
 * @name: path string to check permission for  (NOT NULL)
 * @request: requested permissions
 * @cond: conditional info for this request  (NOT NULL)
 *
 * Do permission check for paths that are predefined.  This fn will
 * be removed once security_sysctl goes away.
 *
 * Returns: %0 else error if access denied or other error
 */
int aa_pathstr_perm(struct aa_profile *profile, const char *op,
		    const char *name, u16 request, struct path_cond *cond)
{
	struct aa_audit_file sa = {
		.base.operation = op,
		.base.gfp_mask = GFP_KERNEL,
		.request = request,
		.name = name,
		.cond = cond,
	};

	sa.perms = aa_str_perms(profile->file.dfa, profile->file.start, sa.name,
				cond,
				NULL);
	if (request & ~sa.perms.allowed)
		sa.base.error = -EACCES;
	return aa_audit_file(profile, &sa);
}

/**
 * aa_path_perm - do permissions check & audit for @path
 * @profile: profile being enforced  (NOT NULL)
 * @operation: name of the operation being enforced  (NOT NULL)
 * @path: path to check permissions of  (NOT NULL)
 * @request: requested permissions
 * @cond: conditional info for this request  (NOT NULL)
 *
 * Returns: %0 else error if access denied or other error
 */
int aa_path_perm(struct aa_profile *profile, const char *operation,
		 struct path *path, u16 request, struct path_cond *cond)
{
	char *buffer, *name;
	struct aa_audit_file sa = {
		.base.operation = operation,
		.base.gfp_mask = GFP_KERNEL,
		.request = request,
		.cond = cond,
	};
	int flags = profile->path_flags |
		(S_ISDIR(cond->mode) ? PATH_IS_DIR : 0);
	/* buffer freed below - name is pointer inside buffer */
	sa.base.error = aa_get_name(path, flags, &buffer, &name);
	sa.name = name;
	if (sa.base.error) {
		sa.perms = nullperms;
		if (sa.base.error == -ENOENT)
			sa.base.info = "Failed name lookup - deleted entry";
		else if (sa.base.error == -ESTALE)
			sa.base.info = "Failed name lookup - disconnected path";
		else if (sa.base.error == -ENAMETOOLONG)
			sa.base.info = "Failed name lookup - name too long";
		else
			sa.base.info = "Failed name lookup";
	} else {
		sa.perms = aa_str_perms(profile->file.dfa, profile->file.start,
					sa.name, cond, NULL);
		if (request & ~sa.perms.allowed)
			sa.base.error = -EACCES;
	}
	sa.base.error = aa_audit_file(profile, &sa);
	kfree(buffer);

	return sa.base.error;
}

/**
 * xindex_is_subset - helper for aa_path_link
 * @link: link permission set
 * @target: target permission set
 *
 * test target x permissions are equal OR a subset of link x permissions
 * this is done as part of the subset test, where a hardlink must have
 * a subset of permissions that the target has.
 *
 * Returns: %1 if subset else %0
 */
static inline bool xindex_is_subset(u16 link, u16 target)
{
	if (((link & ~AA_X_UNSAFE) != (target & ~AA_X_UNSAFE)) ||
	    ((link & AA_X_UNSAFE) && !(target & AA_X_UNSAFE)))
		return 0;

	return 1;
}

/**
 * aa_path_link - Handle hard link permission check
 * @profile: the profile being enforced  (NOT NULL)
 * @old_dentry: the target dentry  (NOT NULL)
 * @new_dir: directory the new link will be created in  (NOT NULL)
 * @new_dentry: the link being created  (NOT NULL)
 *
 * Handle the permission test for a link & target pair.  Permission
 * is encoded as a pair where the link permission is determined
 * first, and if allowed, the target is tested.  The target test
 * is done from the point of the link match (not start of DFA)
 * making the target permission dependent on the link permission match.
 *
 * The subset test if required forces that permissions granted
 * on link are a subset of the permission granted to target.
 *
 * Returns: %0 if allowed else error
 */
int aa_path_link(struct aa_profile *profile, struct dentry *old_dentry,
		 struct path *new_dir, struct dentry *new_dentry)
{
	struct path link = { new_dir->mnt, new_dentry };
	struct path target = { new_dir->mnt, old_dentry };
	struct path_cond cond = {
		old_dentry->d_inode->i_uid,
		old_dentry->d_inode->i_mode
	};
	char *buffer = NULL, *buffer2 = NULL;
	char *lname, *tname;
	struct file_perms perms;
	unsigned int state;

	struct aa_audit_file sa = {
		.base.operation = "link",
		.base.gfp_mask = GFP_KERNEL,
		.request = AA_MAY_LINK,
		.cond = &cond,
		.perms = nullperms,
	};
	/* buffer freed below, lname is pointer in buffer */
	sa.base.error = aa_get_name(&link, profile->path_flags, &buffer,
				    &lname);
	sa.name = lname;
	if (sa.base.error)
		goto audit;

	/* buffer2 freed below, tname is pointer in buffer2 */
	sa.base.error = aa_get_name(&target, profile->path_flags, &buffer2,
				    &tname);
	sa.name2 = tname;
	if (sa.base.error)
		goto audit;

	sa.base.error = -EACCES;

	/* aa_str_perms - handles the case of the dfa being NULL */
	sa.perms = aa_str_perms(profile->file.dfa, profile->file.start, lname,
				&cond, &state);
	sa.perms.audit &= AA_MAY_LINK;
	sa.perms.quiet &= AA_MAY_LINK;
	sa.perms.kill &= AA_MAY_LINK;

	if (!(sa.perms.allowed & AA_MAY_LINK))
		goto audit;

	/* test to see if target can be paired with link */
	state = aa_dfa_null_transition(profile->file.dfa, state,
				       profile->flags & PFLAG_OLD_NULL_TRANS);
	perms = aa_str_perms(profile->file.dfa, state, tname, &cond, NULL);
	if (!(perms.allowed & AA_MAY_LINK)) {
		sa.base.info = "target restricted";
		goto audit;
	}

	/* done if link subset test is not required */
	if (!(perms.allowed & AA_LINK_SUBSET))
		goto done_tests;

	/* Do link perm subset test requiring allowed permission on link are a
	 * subset of the allowed permissions on target.
	 */
	perms = aa_str_perms(profile->file.dfa, profile->file.start, tname,
			     &cond, NULL);

	/* AA_MAY_LINK is not considered in the subset test */
	sa.request = sa.perms.allowed & ~AA_MAY_LINK;
	sa.perms.allowed &= perms.allowed | AA_MAY_LINK;

	sa.request |= AA_AUDIT_FILE_MASK & (sa.perms.allowed & ~perms.allowed);
	if (sa.request & ~sa.perms.allowed) {
		goto audit;
	} else if ((sa.perms.allowed & MAY_EXEC) &&
		   !xindex_is_subset(sa.perms.xindex, perms.xindex)) {
		sa.perms.allowed &= ~MAY_EXEC;
		sa.request |= MAY_EXEC;
		sa.base.info = "link not subset of target";
		goto audit;
	}

done_tests:
	sa.base.error = 0;

audit:
	sa.base.error = aa_audit_file(profile, &sa);
	kfree(buffer);
	kfree(buffer2);

	return sa.base.error;
}

/**
 * aa_is_deleted_file - test if a file has been completely unlinked
 * @dentry: dentry of file to test for deletion  (NOT NULL)
 *
 * Returns: %1 if deleted else %0
 */
static inline bool aa_is_deleted_file(struct dentry *dentry)
{
	if (d_unlinked(dentry) && dentry->d_inode->i_nlink == 0)
		return 1;
	return 0;
}

/**
 * aa_file_common_perm - core permission check & audit for files
 * @profile: profile being enforced   (NOT NULL)
 * @operation: name of operation      (NOT NULL)
 * @file: file to check permissions of  (NOT NULL)
 * @request: requested permissions
 * @name: path name to revalidate permission on  (MAYBE NULL if @error != 0)
 * @error: error result of name lookup when find @name
 *
 * Returns: %0 if access allowed else %1
 */
static int aa_file_common_perm(struct aa_profile *profile,
			       const char *operation, struct file *file,
			       u16 request, const char *name, int error)
{
	struct path_cond cond = {
		.uid = file->f_path.dentry->d_inode->i_uid,
		.mode = file->f_path.dentry->d_inode->i_mode
	};
	struct aa_audit_file sa = {
		.base.operation = operation,
		.base.gfp_mask = GFP_KERNEL,
		.request = request,
		.base.error = error,
		.name = name,
		.cond = &cond,
	};

	if (sa.base.error) {
		sa.perms = nullperms;
		if (sa.base.error == -ENOENT &&
		    aa_is_deleted_file(file->f_path.dentry)) {
			/* Access to open files that are deleted are
			 * give a pass (implicit delegation)
			 */
			sa.base.error = 0;
			sa.perms.allowed = sa.request;
		} else if (sa.base.error == -ENOENT)
			sa.base.info = "Failed name lookup - deleted entry";
		else if (sa.base.error == -ESTALE)
			sa.base.info = "Failed name lookup - disconnected path";
		else if (sa.base.error == -ENAMETOOLONG)
			sa.base.info = "Failed name lookup - name too long";
		else
			sa.base.info = "Failed name lookup";
	} else {
		sa.perms = aa_str_perms(profile->file.dfa, profile->file.start,
					sa.name, &cond, NULL);
		if (request & ~sa.perms.allowed)
			sa.base.error = -EACCES;
	}
	sa.base.error = aa_audit_file(profile, &sa);

	return sa.base.error;
}

/**
 * aa_file_perm - do permission revalidation check & audit for @file
 * @profile: profile being enforced   (NOT NULL)
 * @operation: name of the operation  (NOT NULL)
 * @file: file to revalidate access permissions on  (NOT NULL)
 * @request: requested permissions
 *
 * Returns: %0 if access allowed else error
 */
int aa_file_perm(struct aa_profile *profile, const char *operation,
		 struct file *file, u16 request)
{
	char *buffer, *name;
	umode_t mode = file->f_path.dentry->d_inode->i_mode;
	/* buffer freed below, name is a pointer inside of buffer */
	int flags = profile->path_flags | (S_ISDIR(mode) ? PATH_IS_DIR : 0);
	int error = aa_get_name(&file->f_path, flags, &buffer, &name);

	error = aa_file_common_perm(profile, operation, file, request, name,
				    error);
	kfree(buffer);
	return error;
}
