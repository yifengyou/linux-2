/*
 * AppArmor security module
 *
 * This file contains AppArmor policy manipulation functions
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 *
 * AppArmor policy is based around profiles, which contain the rules a
 * task is confined by.  Every task in the sytem has a profile attached
 * to it determined either by matching "unconfined" tasks against the
 * visible set of profiles or by following a profiles attachment rules.
 *
 * Each profile exists in an profile namespace which is a container of
 * related profiles.  Each namespace contains a special "unconfined" profile,
 * which doesn't enfforce any confinement on a task beyond DAC.
 *
 * Namespace and profile names can be written together in either
 * of two syntaxes.
 *	:namespace:profile - used by kernel interfaces for easy detection
 *	namespace://profile - used by policy
 *
 * Profile names can not start with : or @ or ^ and may not contain \0
 * 
 * Reserved profile names
 *	unconfined - special automatically generated unconfined profile
 *	inherit - special name to indicate profile inheritance
 *	null-XXXX-YYYY - special automically generated learning profiles
 *
 * Namespace names may not start with / or @ and may not contain \0 or :
 * Reserved namespace namespace
 *	default - the default namespace setup by AppArmor
 *	user-XXXX - user defined profiles
 *
 * a // in a profile or namespace name indicates a compound name with the
 * name before the // being the parent and the name after the child.
 *
 * Profile and namespace hierachies serve two different but similar purposes.
 * The namespace contains the set of visible profiles that are considered
 * for attachment.  The hierarchy of namespaces allows for virtualizing
 * the namespace so that for example a chroot can have its own set of profiles
 * which may define some local user namespaces.
 * The profile hierachy severs two distinct purposes,
 * -  it allows for sub profiles or hats, which allows an application to run
 *    subprograms under its own profile with different restriction than it
 *    self, and not have it use the system profile.
 *    eg. if a mail program starts an editor, the policy might make the
 *        restrictions tighter on the editor tighter than the mail program,
 *        and definitely different than general editor restrictions
 * - it allows for binary hierarchy of profiles, so that execution history
 *   is preserved.  This feature isn't exploited by AppArmor reference policy
 *   but is allowed.  NOTE: this is currently suboptimal because profile
 *   aliasing is not currently implemented so that a profile for each
 *   level must be defined.
 *   eg. /bin/bash///bin/ls as a name would indicate /bin/ls was started
 *       from /bin/bash
 *   
 * NOTES:
 *   - hierarchical namespaces are not currently implemented.  Currently
 *     there is only a flat set of namespaces.
 *   - locking of profile lists is currently fairly coarse.  All profile
 *     lists within a namespace use the namespace lock.
 */

#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>

#include "include/apparmor.h"
#include "include/capability.h"
#include "include/file.h"
#include "include/ipc.h"
#include "include/match.h"
#include "include/policy.h"
#include "include/policy_unpack.h"
#include "include/resource.h"
#include "include/sid.h"

/* list of profile namespaces and lock */
LIST_HEAD(ns_list);
DEFINE_RWLOCK(ns_list_lock);

struct aa_namespace *default_namespace;

const char *profile_mode_names[] = {
	"enforce",
	"complain",
	"kill",
};

static bool common_init(struct aa_policy_common *common, const char *name)
{
	/* freed by common_free */
	common->name = kstrdup(name, GFP_KERNEL);
	if (!common->name)
		return 0;
	INIT_LIST_HEAD(&common->list);
	INIT_LIST_HEAD(&common->profiles);
	kref_init(&common->count);
	rwlock_init(&common->lock);

	return 1;
}

static void common_free(struct aa_policy_common *common)
{
	/* still contains profiles -- invalid */
	if (!list_empty(&common->profiles)) {
		AA_ERROR("%s: internal error, "
			 "policy '%s' still contains profiles\n",
			 __func__, common->name);
		BUG();
	}
	if (!list_empty(&common->list)) {
		AA_ERROR("%s: internal error, policy '%s' still on list\n",
			 __func__, common->name);
		BUG();
	}

	kfree(common->name);
}

static struct aa_policy_common *__common_find(struct list_head *head,
					      const char *name)
{
	struct aa_policy_common *common;

	list_for_each_entry(common, head, list) {
		if (!strcmp(common->name, name))
			return common;
	}
	return NULL;
}

static struct aa_policy_common *__common_strn_find(struct list_head *head,
						   const char *str, int len)
{
	struct aa_policy_common *common;

	list_for_each_entry(common, head, list) {
		if (aa_strneq(common->name, str, len))
			return common;
	}

	return NULL;
}

/*
 * Routines for AppArmor namespaces
 */

/**
 * alloc_aa_namespace - allocate, initialize and return a new namespace
 * @name: a preallocated name
 * Returns NULL on failure.
 */
static struct aa_namespace *alloc_aa_namespace(const char *name)
{
	struct aa_namespace *ns;

	ns = kzalloc(sizeof(*ns), GFP_KERNEL);
	AA_DEBUG("%s(%p)\n", __func__, ns);
	if (!ns)
		return NULL;

	if (!common_init(&ns->base, name))
		goto fail_ns;

	/*
	 * null profile is not added to the profile list,
	 * released by free_aa_namespace
	 */
	ns->unconfined = alloc_aa_profile("unconfined");
	if (!ns->unconfined)
		goto fail_unconfined;

	ns->unconfined->sid = aa_alloc_sid(AA_ALLOC_SYS_SID);
	ns->unconfined->flags = PFLAG_UNCONFINED | PFLAG_IX_ON_NAME_ERROR |
	    PFLAG_IMMUTABLE;

	/*
	 * released by free_aa_namespace, however aa_remove_namespace breaks
	 * the cyclic references (ns->unconfined, and unconfinged->ns) and
	 * replaces with refs to default namespace unconfined
	 */
	ns->unconfined->ns = aa_get_namespace(ns);

	return ns;

fail_unconfined:
	kfree(ns->base.name);
fail_ns:
	kfree(ns);
	return NULL;
}

/**
 * free_aa_namespace - free a profile namespace
 * @namespace: the namespace to free
 *
 * Requires: All references to the namespace must have been put, if the
 *           namespace was referenced by a profile confining a task,
 */
static void free_aa_namespace(struct aa_namespace *ns)
{
	if (!ns)
		return;

	common_free(&ns->base);

	if (ns->unconfined && ns->unconfined->ns == ns)
		ns->unconfined->ns = NULL;

	aa_put_profile(ns->unconfined);
	kzfree(ns);
}

/**
 * free_aa_namespace_kref - free aa_namespace by kref (see aa_put_namespace)
 * @kr: kref callback for freeing of a namespace
 */
void free_aa_namespace_kref(struct kref *kref)
{
	free_aa_namespace(container_of(kref, struct aa_namespace, base.count));
}

/**
 * aa_alloc_default_namespace - allocate the base default namespace
 *
 * Returns 0 on success else error
 *
 */
int aa_alloc_default_namespace(void)
{
	struct aa_namespace *ns;
	/* released by aa_free_default_namespace - used as list ref*/
	ns = alloc_aa_namespace("default");
	if (!ns)
		return -ENOMEM;

	/* released by aa_free_default_namespace - global var ref*/
	default_namespace = aa_get_namespace(ns);
	write_lock(&ns_list_lock);
	list_add(&ns->base.list, &ns_list);
	write_unlock(&ns_list_lock);

	return 0;
}

void aa_free_default_namespace(void)
{
	write_lock(&ns_list_lock);
	list_del_init(&default_namespace->base.list);
	write_unlock(&ns_list_lock);
	/* drop the list ref and the global default_namespace ref */
	aa_put_namespace(default_namespace);
	aa_put_namespace(default_namespace);
	default_namespace = NULL;
}

/**
 * __aa_find_namespace - find a namespace on a list by @name
 * @name - name of namespace to look for
 *
 * Return: unrefcounted namespace
 *
 * Requires: ns_list_lock be held
 */
static struct aa_namespace *__aa_find_namespace(struct list_head *head,
						const char *name)
{
	return (struct aa_namespace *)__common_find(head, name);
}

/**
 * aa_find_namespace  -  look up a profile namespace on the namespace list
 * @name: name of namespace to find
 *
 * Return: a pointer to the namespace on the list, or NULL if no namespace
 * called @name exists.
 *
 * refcount released by caller
 */
struct aa_namespace *aa_find_namespace(const char *name)
{
	struct aa_namespace *ns = NULL;

	read_lock(&ns_list_lock);
	ns = aa_get_namespace(__aa_find_namespace(&ns_list, name));
	read_unlock(&ns_list_lock);

	return ns;
}

/**
 * aa_prepare_namespace - find an existing or create a new namespace of @name
 * @name: the namespace to find or add
 *
 * Return: refcounted namespace or NULL if failed to create one
 */
static struct aa_namespace *aa_prepare_namespace(const char *name)
{
	struct aa_namespace *ns;

	write_lock(&ns_list_lock);
	if (name)
		/* released by caller */
		ns = aa_get_namespace(__aa_find_namespace(&ns_list, name));
	else
		/* released by caller */
		ns = aa_get_namespace(default_namespace);
	if (!ns) {
		/* name && namespace not found */
		struct aa_namespace *new_ns;
		write_unlock(&ns_list_lock);
		new_ns = alloc_aa_namespace(name);
		if (!new_ns)
			return NULL;
		write_lock(&ns_list_lock);
		/* test for race when new_ns was allocated */
		ns = __aa_find_namespace(&ns_list, name);
		if (!ns) {
			list_add(&new_ns->base.list, &ns_list);
			/* add list ref */
			ns = aa_get_namespace(new_ns);
		} else {
			/* raced so free the new one */
			free_aa_namespace(new_ns);
			/* get reference on namespace */
			aa_get_namespace(ns);
		}
	}
	write_unlock(&ns_list_lock);

	/* return ref */
	return ns;
}

/**
 * __aa_add_profile - add a profile to a list
 * @common: the namespace or profile list to add it to
 * @profile: the profile to add
 *
 * refcount @profile, should be put by __aa_remove_profile
 *
 * Requires: namespace list lock be held, or list not be shared
 */
static void __aa_add_profile(struct aa_policy_common *common,
			     struct aa_profile *profile)
{
	list_add(&profile->base.list, &common->profiles);
	if (!(profile->flags & PFLAG_NO_LIST_REF))
		/* get list reference */
		aa_get_profile(profile);
}

/**
 * __aa_remove_profile - remove a profile from the list it is one
 * @profile: the profile to remove
 *
 * remove a profile from the list, warning generally removal should
 * be done with __aa_replace_profile as most profile removals are
 * replacements to the unconfined profile.
 *
 * put @profile refcount
 *
 * Requires: namespace list lock be held, or list not be shared
 */
static void __aa_remove_profile(struct aa_profile *profile)
{
	list_del_init(&profile->base.list);
	if (!(profile->flags & PFLAG_NO_LIST_REF))
		/* release list reference */
		aa_put_profile(profile);
}

/**
 * __aa_replace_profile - replace @old with @new on a list
 * @old: profile to be replaced
 * @new: profile to replace @old with
 *
 * Will duplicaticate and refcount elements that @new inherits from @old
 * and will inherit @old children.  If new is NULL it will replace to the
 * unconfined profile for old's namespace.
 *
 * refcount @new for list, put @old list refcount
 *
 * Requires: namespace list lock be held, or list not be shared
 */
static void __aa_replace_profile(struct aa_profile *old,
				 struct aa_profile *new)
{
	struct aa_policy_common *common;
	struct aa_profile *child, *tmp;

	if (old->parent)
		common = &old->parent->base;
	else
		common = &old->ns->base;

	if (new) {
		/* released when @new is freed */
		new->parent = aa_get_profile(old->parent);
		new->ns = aa_get_namespace(old->ns);
		new->sid = old->sid;
		__aa_add_profile(common, new);
	} else {
		/* refcount not taken, held via @old refcount */
		new = old->ns->unconfined;
	}

	/* inherit children */
	list_for_each_entry_safe(child, tmp, &old->base.profiles, base.list) {
		aa_put_profile(child->parent);
		child->parent = aa_get_profile(new);
		/* list refcount transfered to @new*/
		list_move(&child->base.list, &new->base.profiles);
	}

	/* released by free_aa_profile */
	old->replacedby = aa_get_profile(new);
	__aa_remove_profile(old);
}

/**
 * __aa_profile_list_release - remove all profiles on the list and put refs
 * @head: list of profiles
 *
 * Requires: namespace lock be held
 */
static void __aa_profile_list_release(struct list_head *head)
{
	struct aa_profile *profile, *tmp;
	list_for_each_entry_safe(profile, tmp, head, base.list) {
		/* release any children lists first */
		__aa_profile_list_release(&profile->base.profiles);
		__aa_replace_profile(profile, NULL);
	}
}

/**
 * __aa_remove_namespace - remove a namespace and all its children
 * @ns: namespace to be removed
 * 
 * Requires: ns_list_lock && ns->base.lock be held
 */
static void __aa_remove_namespace(struct aa_namespace *ns)
{
	struct aa_profile *unconfined = ns->unconfined;
	/* remove ns from namespace list */
	list_del_init(&ns->base.list);

	/*
	 * break the ns, unconfined profile cyclic reference and forward
	 * all new unconfined profiles requests to the default namespace
	 * This will result in all confined tasks that have a profile
	 * being removed inheriting the default->unconfined profile.
	 */
	ns->unconfined = aa_get_profile(default_namespace->unconfined);
	__aa_profile_list_release(&ns->base.profiles);
	/* release original ns->unconfined ref */
	aa_put_profile(unconfined);
	/* release ns->base.list ref, from removal above */
	aa_put_namespace(ns);
}


/**
 * aa_profilelist_release - remove all namespaces and all associated profiles
 */
void aa_profile_ns_list_release(void)
{
	struct aa_namespace *ns, *tmp;

	/* Remove and release all the profiles on namespace profile lists. */
	write_lock(&ns_list_lock);
	list_for_each_entry_safe(ns, tmp, &ns_list, base.list) {
		write_lock(&ns->base.lock);
		__aa_remove_namespace(ns);
		write_unlock(&ns->base.lock);
	}
	write_unlock(&ns_list_lock);
}

/* fqname in this context does not have a namespace name prepended */
static const char *fqname_subname(const char *name)
{
	char *split;
	/* check for namespace which begins with a : and ends with : or \0 */
	name = strstrip((char *)name);
	for (split = strstr(name, "//"); split; split = strstr(name, "//"))
		name = split + 2;

	return name;
}

/**
 * alloc_aa_profile - allocate, initialize and return a new profile
 * @fqname: name of the profile
 *
 * Returns NULL on failure, else refcounted profile
 */
struct aa_profile *alloc_aa_profile(const char *fqname)
{
	struct aa_profile *profile;

	/* freed by free_aa_profile - usually through aa_put_profile */
	profile = kzalloc(sizeof(*profile), GFP_KERNEL);
	if (!profile)
		return NULL;

	if (!common_init(&profile->base, fqname)) {
		kfree(profile);
		return NULL;
	}

	profile->fqname = profile->base.name;
	/* base.name is a substring of fqname */
	profile->base.name =
	    (char *)fqname_subname((const char *)profile->fqname);

	/* return ref */
	return profile;
}

/**
 * aa_new_null_profile - create a new null-X learning profile
 * @parent: profile that caused this profile to be created
 * @hat: true if the null- learning profile is a hat
 *
 * Create a null- complain mode profile used in learning mode.  The name of
 * the profile is unique and follows the format of parent//null-sid.
 *
 * null profiles are added to the profile list but the list does not
 * hold a count on them so that they are automatically released when
 * not in use.
 */
struct aa_profile *aa_alloc_null_profile(struct aa_profile *parent, int hat)
{
	struct aa_profile *profile = NULL;
	char *name;
	u32 sid = aa_alloc_sid(AA_ALLOC_SYS_SID);

	/* freed below */
	name = kmalloc(strlen(parent->fqname) + 2 + 7 + 8, GFP_KERNEL);
	if (!name)
		goto fail;
	sprintf(name, "%s//null-%x", parent->fqname, sid);

	profile = alloc_aa_profile(name);
	kfree(name);
	if (!profile)
		goto fail;

	profile->sid = aa_alloc_sid(AA_ALLOC_SYS_SID);
	profile->mode = APPARMOR_COMPLAIN;
	profile->flags = PFLAG_NULL | PFLAG_NO_LIST_REF;
	if (hat)
		profile->flags |= PFLAG_HAT;

	/* released on free_aa_profile */
	profile->parent = aa_get_profile(parent);
	profile->ns = aa_get_namespace(parent->ns);

	write_lock(&profile->ns->base.lock);
	__aa_add_profile(&parent->base, profile);
	write_unlock(&profile->ns->base.lock);

	return profile;

fail:
	aa_free_sid(sid);
	return NULL;
}

/**
 * free_aa_profile_kref - free aa_profile by kref (called by aa_put_profile)
 * @kr: kref callback for freeing of a profile
 */
void free_aa_profile_kref(struct kref *kref)
{
	struct aa_profile *p = container_of(kref, struct aa_profile,
					    base.count);

	free_aa_profile(p);
}

/**
 * free_aa_profile - free a profile
 * @profile: the profile to free
 *
 * Free a profile, its hats and null_profile. All references to the profile,
 * its hats and null_profile must have been put.
 *
 * If the profile was referenced from a task context, free_aa_profile() will
 * be called from an rcu callback routine, so we must not sleep here.
 */
void free_aa_profile(struct aa_profile *profile)
{
	AA_DEBUG("%s(%p)\n", __func__, profile);

	if (!profile)
		return;

	/*
	 * profile can still be on the list if the list doesn't hold a
	 * reference.  There is no race as NULL profiles can't be attached
	 */
	if (!list_empty(&profile->base.list)) {
		if ((profile->flags & PFLAG_NULL) && profile->ns) {
			write_lock(&profile->ns->base.lock);
			list_del_init(&profile->base.list);
			write_unlock(&profile->ns->base.lock);
		} else {
			AA_ERROR("%s: internal error, "
				 "profile '%s' still on ns list\n",
				 __func__, profile->base.name);
			BUG();
		}
	}

	/* profile->name is a substring of fqname */
	profile->base.name = NULL;
	/* free children profiles */
	common_free(&profile->base);

	BUG_ON(!list_empty(&profile->base.profiles));

	kfree(profile->fqname);

	aa_put_namespace(profile->ns);
	aa_put_profile(profile->parent);

	aa_free_file_rules(&profile->file);
	aa_free_cap_rules(&profile->caps);
	aa_free_net_rules(&profile->net);
	aa_free_rlimit_rules(&profile->rlimits);

	aa_free_sid(profile->sid);
	aa_dfa_free(profile->xmatch);

	if (profile->replacedby)
		aa_put_profile(profile->replacedby);

	kzfree(profile);
}

/* TODO: profile count accounting - setup in remove */

/**
 * __aa_find_child - find a profile on @head list with a name matching @name
 * @head: list to search
 * @name: name of profile
 *
 * Requires: ns lock protecting list be held
 *
 * Returns unrefcounted profile ptr, or NULL if not found
 */
static struct aa_profile *__aa_find_child(struct list_head *head,
					  const char *name)
{
	return (struct aa_profile *)__common_find(head, name);
}

/**
 * __aa_strn_find_child - find a profile on @head list using substring of @name
 * @head: list to search
 * @name: name of profile
 * @len: length of @name substring to match
 *
 * Requires: ns lock protecting list be held
 *
 * Returns unrefcounted profile ptr, or NULL if not found
 */
static struct aa_profile *__aa_strn_find_child(struct list_head *head,
					       const char *name, int len)
{
	return (struct aa_profile *)__common_strn_find(head, name, len);
}

/**
 * aa_find_child - find a profile by @name in @parent
 * @parent: profile to search
 * @name: profile name to search for
 *
 * Returns a ref counted profile or NULL if not found
 */
struct aa_profile *aa_find_child(struct aa_profile *parent, const char *name)
{
	struct aa_profile *profile;

	read_lock(&parent->ns->base.lock);
	profile = aa_get_profile(__aa_find_child(&parent->base.profiles, name));
	read_unlock(&parent->ns->base.lock);

	return profile;
}

/**
 * __aa_find_parent - lookup the parent of a profile of name @fqname
 * @ns: namespace to lookup profile in
 * @fqname: fully qualified profile name to find parent of
 *
 * Lookups up the parent of a fully qualified profile name, the profile
 * that matches fqname does not need to exist, in general this
 * is used to load a new profile.
 *
 * Requires: ns->base.lock be held
 *
 * Returns: unrefcounted common or NULL if not found
 */
static struct aa_policy_common *__aa_find_parent(struct aa_namespace *ns,
						 const char *fqname)
{
	struct aa_policy_common *common;
	struct aa_profile *profile = NULL;
	char *split;

	common = &ns->base;

	for (split = strstr(fqname, "//"); split;) {
		profile = __aa_strn_find_child(&common->profiles, fqname,
					       split - fqname);
		if (!profile)
			return NULL;
		common = &profile->base;
		fqname = split + 2;
		split = strstr(fqname, "//");
	}
	if (!profile)
		return &ns->base;
	return &profile->base;
}

/**
 * __aa_find_profile - lookup the profile matching @fqname
 * @ns: namespace to search for profile in
 * @fqname: fully qualified profile name
 *
 * Requires: ns->base.lock be held
 *
 * Returns: unrefcounted profile pointer or NULL if not found
 */
static struct aa_profile *__aa_find_profile(struct aa_namespace *ns,
					    const char *fqname)
{
	struct aa_policy_common *common;
	struct aa_profile *profile = NULL;
	char *split;

	common = &ns->base;
	for (split = strstr(fqname, "//"); split;) {
		profile = __aa_strn_find_child(&common->profiles, fqname,
						 split - fqname);
		if (!profile)
			return NULL;

		common = &profile->base;
		fqname = split + 2;
		split = strstr(fqname, "//");
	}

	profile = __aa_find_child(&common->profiles, fqname);

	return profile;
}

/**
 * aa_find_profile_by_name - find a profile by its full or partial name
 * @ns: the namespace to start from
 * @fqname: name to do lookup on.  Does not contain namespace prefix
 *
 * Returns: refcounted profile or NULL if not found
 */
struct aa_profile *aa_find_profile(struct aa_namespace *ns, const char *fqname)
{
	struct aa_profile *profile;

	read_lock(&ns->base.lock);
	profile = aa_get_profile(__aa_find_profile(ns, fqname));
	read_unlock(&ns->base.lock);
	return profile;
}

/**
 * aa_interface_add_profiles - Unpack and add new profile(s) to the profile list
 * @data: serialized data stream
 * @size: size of the serialized data stream
 */
ssize_t aa_interface_add_profiles(void *udata, size_t size)
{
	struct aa_profile *profile = NULL;
	struct aa_namespace *ns = NULL;
	struct aa_policy_common *common;
	ssize_t error;
	struct aa_audit_iface sa = {
		.base.operation = "profile_load",
		.base.gfp_mask = GFP_ATOMIC,
	};

	/* check if loading policy is locked out */
	if (aa_g_lock_policy) {
		sa.base.info = "policy locked";
		sa.base.error = -EACCES;
		goto fail;
	}

	/* released below */
	profile = aa_unpack(udata, size, &sa);
	if (IS_ERR(profile)) {
		sa.base.error = PTR_ERR(profile);
		goto fail;
	}

	/* released below */
	ns = aa_prepare_namespace(sa.name2);
	if (IS_ERR(ns)) {
		sa.base.info = "failed to prepare namespace";
		sa.base.error = PTR_ERR(ns);
		goto fail;
	}
	/* profiles are currently loaded flat with fqnames */
	sa.name = profile->fqname;

	write_lock(&ns->base.lock);

	/* no ref on common only use inside of lock */
	common = __aa_find_parent(ns, sa.name);
	if (!common) {
		sa.base.info = "parent does not exist";
		sa.base.error = -ENOENT;
		goto audit;
	}

	if (common != &ns->base)
		/* released on profile replacement or free_aa_profile */
		profile->parent = aa_get_profile((struct aa_profile *)common);

	if (__aa_find_child(&common->profiles, profile->base.name)) {
		/* A profile with this name exists already. */
		sa.base.info = "profile already exists";
		sa.base.error = -EEXIST;
	}

audit:
	error = aa_audit_iface(&sa);
	if (!error) {
		/* released on free_aa_profile */
		profile->sid = aa_alloc_sid(AA_ALLOC_SYS_SID);
		profile->ns = aa_get_namespace(ns);
		__aa_add_profile(common, profile);
	}

	write_unlock(&ns->base.lock);

out:
	aa_put_namespace(ns);
	aa_put_profile(profile);

	if (error)
		return error;
	return size;

fail:
	error = aa_audit_iface(&sa);
	goto out;
}

/**
 * aa_interface_replace_profiles - replace profile(s) on the profile list
 * @udata: serialized data stream
 * @size: size of the serialized data stream
 *
 * unpack and replace a profile on the profile list and uses of that profile
 * by any aa_task_context.  If the profile does not exist on the profile list
 * it is added.  Return %0 or error.
 */
ssize_t aa_interface_replace_profiles(void *udata, size_t size)
{
	struct aa_policy_common *common;
	struct aa_profile *old_profile = NULL, *new_profile = NULL;
	struct aa_namespace *ns;
	ssize_t error;
	struct aa_audit_iface sa = {
		.base.operation = "profile_replace",
		.base.gfp_mask = GFP_ATOMIC,
	};

	/* check if loading policy is locked out */
	if (aa_g_lock_policy) {
		sa.base.info = "policy locked";
		sa.base.error = -EACCES;
		goto fail;
	}

	new_profile = aa_unpack(udata, size, &sa);
	if (IS_ERR(new_profile)) {
		sa.base.error = PTR_ERR(new_profile);
		goto fail;
	}

	ns = aa_prepare_namespace(sa.name2);
	if (!ns) {
		sa.base.info = "failed to prepare namespace";
		sa.base.error = -ENOMEM;
		goto fail;
	}

	sa.name = new_profile->fqname;

	write_lock(&ns->base.lock);
	/* no ref on common only use inside lock */
	common = __aa_find_parent(ns, sa.name);

	if (!common) {
		sa.base.info = "parent does not exist";
		sa.base.error = -ENOENT;
		goto audit;
	}

	old_profile = __aa_find_child(&common->profiles,
				      new_profile->base.name);
	/* released below */
	aa_get_profile(old_profile);
	if (old_profile && old_profile->flags & PFLAG_IMMUTABLE) {
		sa.base.info = "cannot replace immutible profile";
		sa.base.error = -EPERM;
	}

audit:
	if (!old_profile)
		sa.base.operation = "profile_load";

	error = aa_audit_iface(&sa);

	if (!error) {
		if (old_profile) {
			__aa_replace_profile(old_profile, new_profile);
		} else {
			if (common != &ns->base)
				new_profile->parent = aa_get_profile(
					(struct aa_profile *) common);
			__aa_add_profile(common, new_profile);
			new_profile->sid = aa_alloc_sid(AA_ALLOC_SYS_SID);
			new_profile->ns = aa_get_namespace(ns);
		}
	}
	write_unlock(&ns->base.lock);

out:
	aa_put_namespace(ns);
	aa_put_profile(old_profile);
	aa_put_profile(new_profile);
	if (error)
		return error;
	return size;

fail:
	error = aa_audit_iface(&sa);
	goto out;
}

/**
 * aa_interface_remove_profiles - remove profile(s) from the system
 * @name: name of the profile to remove
 * @size: size of the name
 *
 * remove a profile from the profile list and all aa_task_context references
 * to said profile.
 * NOTE: removing confinement does not restore rlimits to preconfinemnet values
 */
ssize_t aa_interface_remove_profiles(char *name, size_t size)
{
	struct aa_namespace *ns = NULL;
	struct aa_profile *profile = NULL;
	struct aa_audit_iface sa = {
		.base.operation = "profile_remove",
		.base.gfp_mask = GFP_ATOMIC,
	};
	int error;

	/* check if loading policy is locked out */
	if (aa_g_lock_policy) {
		sa.base.info = "policy locked";
		sa.base.error = -EACCES;
		goto fail;
	}

	write_lock(&ns_list_lock);
	if (name[0] == ':') {
		char *ns_name;
		name = aa_split_name_from_ns(name, &ns_name);
		if (name)
			/* released below */
			ns = aa_get_namespace(__aa_find_namespace(&ns_list,
								  ns_name));
	} else {
		/* released below */
		ns = aa_get_namespace(default_namespace);
	}

	if (!ns) {
		sa.base.info = "failed: namespace does not exist";
		sa.base.error = -ENOENT;
		goto fail_ns_list_lock;
	}

	sa.name2 = ns->base.name;
	write_lock(&ns->base.lock);
	if (!name) {
		/* remove namespace */
		if (ns == default_namespace)
			__aa_profile_list_release(&ns->base.profiles);
		else
			__aa_remove_namespace(ns);
	} else {
		/* remove profile */
		profile = aa_get_profile(__aa_find_profile(ns, name));
		if (!profile) {
			sa.name = name;
			sa.base.error = -ENOENT;
			sa.base.info = "failed: profile does not exist";
			goto fail_ns_lock;
		}
		sa.name = profile->fqname;
		__aa_profile_list_release(&profile->base.profiles);
		__aa_replace_profile(profile, NULL);
	}
	write_unlock(&ns->base.lock);
	write_unlock(&ns_list_lock);

	/* don't fail removal if audit fails */
	(void) aa_audit_iface(&sa);
	aa_put_namespace(ns);
	aa_put_profile(profile);
	return size;

fail_ns_lock:
	write_unlock(&ns->base.lock);

fail_ns_list_lock:
	write_unlock(&ns_list_lock);

fail:
	error = aa_audit_iface(&sa);
	return error;
}