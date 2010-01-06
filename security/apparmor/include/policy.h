/*
 * AppArmor security module
 *
 * This file contains AppArmor policy definitions.
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2010 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#ifndef __AA_POLICY_H
#define __AA_POLICY_H

#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/kref.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/socket.h>

#include "apparmor.h"
#include "audit.h"
#include "capability.h"
#include "domain.h"
#include "file.h"
#include "net.h"
#include "resource.h"

extern const char *profile_mode_names[];
#define APPARMOR_NAMES_MAX_INDEX 3

#define PROFILE_COMPLAIN(_profile)				\
	((aa_g_profile_mode == APPARMOR_COMPLAIN) || ((_profile) &&	\
					(_profile)->mode == APPARMOR_COMPLAIN))

#define PROFILE_KILL(_profile)					\
	((aa_g_profile_mode == APPARMOR_KILL) || ((_profile) &&	\
					(_profile)->mode == APPARMOR_KILL))

#define PROFILE_IS_HAT(_profile) \
	((_profile) && (_profile)->flags & PFLAG_HAT)

/*
 * FIXME: currently need a clean way to replace and remove profiles as a
 * set.  It should be done at the namespace level.
 * Either, with a set of profiles loaded at the namespace level or via
 * a mark and remove marked interface.
 */
enum profile_mode {
	APPARMOR_ENFORCE,	/* enforce access rules */
	APPARMOR_COMPLAIN,	/* allow and log access violations */
	APPARMOR_KILL,		/* kill task on access violation */
};

enum profile_flags {
	PFLAG_HAT = 1,			/* profile is a hat */
	PFLAG_UNCONFINED = 2,		/* profile is the unconfined profile */
	PFLAG_NULL = 4,			/* profile is null learning profile */
	PFLAG_IX_ON_NAME_ERROR = 8,	/* fallback to ix on name lookup fail */
	PFLAG_IMMUTABLE = 0x10,		/* don't allow changes/replacement */
	PFLAG_USER_DEFINED = 0x20,	/* user based profile */
	PFLAG_NO_LIST_REF = 0x40,	/* list doesn't keep profile ref */
	PFLAG_MMAP_MIN_ADDR = 0x80,	/* profile controls mmap_min_addr */
	PFLAG_DELETED_NAMES = 0x100,	/* mediate deleted paths */
	PFLAG_CONNECT_PATH = 0x200,	/* connect disconnected paths to / */
	PFLAG_OLD_NULL_TRANS = 0x400,	/* use // as the null transition */
};

#define AA_NEW_SID 0

struct aa_profile;

/* struct aa_policy_common - common part of both namespaces and profiles
 * @name: name of the object
 * @hname - The hierarchical name
 * @count: reference count of the obj
 * lock: lock for modifying the object
 * @list: list object is on
 * @profiles: head of the profiles list contained in the object
 */
struct aa_policy_common {
	char *name;
	char *hname;
	struct kref count;
	rwlock_t lock;
	struct list_head list;
	struct list_head profiles;
};

/* struct aa_ns_acct - accounting of profiles in namespace
 * @max_size: maximum space allowed for all profiles in namespace
 * @max_count: maximum number of profiles that can be in this namespace
 * @size: current size of profiles
 * @count: current count of profiles (includes null profiles)
 */
struct aa_ns_acct {
	int max_size;
	int max_count;
	int size;
	int count;
};

/* struct aa_namespace - namespace for a set of profiles
 * @name: the name of the namespace
 * @list: list the namespace is on
 * @profiles: list of profile in the namespace
 * @acct: accounting for the namespace
 * @profile_count: count of profiles on @profiles list
 * @size: accounting of how much memory is consumed by the contained profiles
 * @unconfined: special unconfined profile for the namespace
 * @count: reference count on the namespace
 * @lock: lock for adding/removing profile to the namespace
 *
 * An aa_namespace defines the set profiles that are searched to determine
 * which profile to attach to a task.  Profiles can not be shared between
 * aa_namespaces and profile names within a namespace are guarenteed to be
 * unique.  When profiles in seperate namespaces have the same name they
 * are NOT considered to be equivalent.
 *
 * Namespace names must be unique and can not contain the characters :/\0
 *
 * FIXME TODO: add vserver support so a vserer gets a default namespace
 */
struct aa_namespace {
	struct aa_policy_common base;
	struct aa_ns_acct acct;
	int is_stale;
	struct aa_profile *unconfined;
};

/* struct aa_profile - basic confinement data
 * @base - base componets of the profile (name, refcount, lists, lock ...)
 * @ns: namespace the profile is in
 * @parent: parent profile of this profile, if one exists
 * @replacedby: is set profile that replaced this profile
 * @xmatch: optional extended matching for unconfined executables names
 * @xmatch_plen: xmatch prefix len, used to determine xmatch priority
 * @sid: the unique security id number of this profile
 * @audit: the auditing mode of the profile
 * @mode: the enforcement mode of the profile
 * @flags: flags controlling profile behavior
 * @size: the memory consumed by this profiles rules
 * @file: The set of rules governing basic file access and domain transitions
 * @caps: capabilities for the profile
 * @net: network controls for the profile
 * @rlimits: rlimits for the profile
 *
 * The AppArmor profile contains the basic confinement data.  Each profile
 * has a name, and exist in a namespace.  The @name and @exec_match are
 * used to determine profile attachment against unconfined tasks.  All other
 * attachments are determined by in profile X transition rules.
 *
 * The @replacedby field is write protected by the profile lock.  Reads
 * are assumed to be atomic, and are done without locking.
 *
 * Profiles have a hierachy where hats and children profiles keep
 * a reference to their parent.
 *
 * Profile names can not begin with a : and can not contain the \0
 * character.  If a profile name begins with / it will be considered when
 * determining profile attachment on "unconfined" tasks.
 */
struct aa_profile {
	struct aa_policy_common base;

	struct aa_namespace *ns;
	struct aa_profile *parent;
	union {
		struct aa_profile *replacedby;
		const char *rename;
	};
	struct aa_dfa *xmatch;
	int xmatch_len;
	u32 sid;
	enum audit_mode audit;
	enum profile_mode mode;
	u32 flags;
	int size;

	unsigned long mmap_min_addr;

	struct aa_file_rules file;
	struct aa_caps caps;
	struct aa_net net;
	struct aa_rlimit rlimits;
};

extern struct list_head ns_list;
extern rwlock_t ns_list_lock;

extern struct aa_namespace *default_namespace;
extern enum profile_mode aa_g_profile_mode;

void aa_add_profile(struct aa_policy_common *common,
		    struct aa_profile *profile);

int aa_alloc_default_namespace(void);
void aa_free_default_namespace(void);
void aa_free_namespace_kref(struct kref *kref);

struct aa_namespace *aa_find_namespace(const char *name);
void aa_profile_ns_list_release(void);

static inline struct aa_policy_common *aa_get_common(struct aa_policy_common *c)
{
	if (c)
		kref_get(&c->count);

	return c;
}

static inline struct aa_namespace *aa_get_namespace(struct aa_namespace *ns)
{
	if (ns)
		kref_get(&(ns->base.count));

	return ns;
}

static inline void aa_put_namespace(struct aa_namespace *ns)
{
	if (ns)
		kref_put(&ns->base.count, aa_free_namespace_kref);
}

struct aa_profile *aa_alloc_profile(const char *name);
struct aa_profile *aa_new_null_profile(struct aa_profile *parent, int hat);
void aa_free_profile_kref(struct kref *kref);
struct aa_profile *aa_find_child(struct aa_profile *parent, const char *name);
struct aa_profile *aa_find_profile(struct aa_namespace *ns, const char *name);
struct aa_profile *aa_match_profile(struct aa_namespace *ns, const char *name);

ssize_t aa_interface_replace_profiles(void *udata, size_t size, bool add_only);
ssize_t aa_interface_remove_profiles(char *name, size_t size);

/**
 * aa_confined - test whether @profile is confining
 * @profile: profile to test if is confining
 *
 * Returns: true if profile will confine a task
 */
static inline bool aa_confined(struct aa_profile *profile)
{
	return !(profile->flags & PFLAG_UNCONFINED);
}

/**
 * aa_filter_profile - filter out profiles that shouldn't be used to mediate
 * @profile: profile to filter
 *
 * does not change refcounts
 *
 * Return: @profile or NULL if it is filtered
 */
static inline struct aa_profile *aa_filter_profile(struct aa_profile *profile)
{
	if (!aa_confined(profile))
		return NULL;
	return profile;
}

/**
 * aa_profile_newest - find the newest version of @profile
 * @profile: the profile to check for newer versions of
 *
 * Find the newest version of @profile, if @profile is the newest version
 * return @profile.
 *
 * NOTE: the profile returned is not refcounted, The refcount on @profile
 * must be held until the caller decides what to do with the returned newest
 * version.
 */
static inline struct aa_profile *aa_profile_newest(struct aa_profile *profile)
{
	if (unlikely(profile && profile->replacedby))
		for (; profile->replacedby; profile = profile->replacedby) ;

	return profile;
}

/**
 * aa_confining_profile - find the newest confining profile version
 * @p - profile to check if newest version
 *
 * NOTE: the profile returned is not refcounted, The refcount on @p
 * must be held until the caller decides what to do with the returned newest
 * version.
 */
static inline struct aa_profile *aa_confining_profile(struct aa_profile *p)
{
	return aa_filter_profile(aa_profile_newest(p));
}

/**
 * aa_get_profile - increment refcount on profile @p
 * @p: profile
 */
static inline struct aa_profile *aa_get_profile(struct aa_profile *p)
{
	if (p)
		kref_get(&(p->base.count));

	return p;
}

/**
 * aa_put_profile - decrement refcount on profile @p
 * @p: profile
 */
static inline void aa_put_profile(struct aa_profile *p)
{
	if (p)
		kref_put(&p->base.count, aa_free_profile_kref);
}

static inline int PROFILE_AUDIT_MODE(struct aa_profile *profile)
{
	if (aa_g_audit != AUDIT_NORMAL)
		return aa_g_audit;
	if (profile)
		return profile->audit;
	return AUDIT_NORMAL;
}

#endif /* __AA_POLICY_H */
