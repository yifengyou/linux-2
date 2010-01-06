/*
 * AppArmor security module
 *
 * This file contains AppArmor LSM hooks.
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2010 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include <linux/security.h>
#include <linux/moduleparam.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/ptrace.h>
#include <linux/ctype.h>
#include <linux/sysctl.h>
#include <linux/audit.h>
#include <net/sock.h>

#include "include/apparmor.h"
#include "include/apparmorfs.h"
#include "include/audit.h"
#include "include/capability.h"
#include "include/context.h"
#include "include/file.h"
#include "include/ipc.h"
#include "include/net.h"
#include "include/path.h"
#include "include/policy.h"
#include "include/procattr.h"

/* Flag indicating whether initialization completed */
int apparmor_initialized;

/*
 * LSM hook functions
 */

/*
 * free the associated aa_task_context and put its profiles
 */
static void apparmor_cred_free(struct cred *cred)
{
	aa_free_task_context(cred->security);
	cred->security = NULL;
}

/*
 * allocate the apparmor part of blank credentials
 */
static int apparmor_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	/* freed by apparmor_cred_free */
	struct aa_task_context *cxt = aa_alloc_task_context(gfp);
	if (cxt)
		return -ENOMEM;

	cred->security = cxt;
	return 0;
}

/*
 * prepare new aa_task_context for modification by prepare_cred block
 */
static int apparmor_cred_prepare(struct cred *new, const struct cred *old,
				 gfp_t gfp)
{
	/* freed by apparmor_cred_free */
	struct aa_task_context *cxt = aa_alloc_task_context(gfp);
	if (!cxt)
		return -ENOMEM;

	aa_dup_task_context(cxt, old->security);
	new->security = cxt;
	return 0;
}

/*
 * transfer the apparmor data to a blank set of creds
 */
static void apparmor_cred_transfer(struct cred *new, const struct cred *old)
{
	const struct aa_task_context *old_cxt = old->security;
	struct aa_task_context *new_cxt = new->security;

	aa_dup_task_context(new_cxt, old_cxt);
}

static int apparmor_ptrace_access_check(struct task_struct *child,
					unsigned int mode)
{
	int rc;

	rc = cap_ptrace_access_check(child, mode);
	if (rc)
		return rc;

	return aa_ptrace(current, child, mode);
}

static int apparmor_ptrace_traceme(struct task_struct *parent)
{
	return aa_ptrace(parent, current, PTRACE_MODE_ATTACH);
}

/* Derived from security/commoncap.c:cap_capget */
static int apparmor_capget(struct task_struct *target, kernel_cap_t *effective,
			   kernel_cap_t *inheritable, kernel_cap_t *permitted)
{
	struct aa_profile *profile;
	const struct cred *cred;

	rcu_read_lock();
	cred = __task_cred(target);
	profile = aa_cred_policy(cred);

	*effective = cred->cap_effective;
	*inheritable = cred->cap_inheritable;
	*permitted = cred->cap_permitted;

	if (profile) {
		*effective = cap_combine(*effective, profile->caps.set);
		*effective = cap_intersect(*effective, profile->caps.allowed);
	}
	rcu_read_unlock();

	return 0;
}

static int apparmor_capable(struct task_struct *task, const struct cred *cred,
			    int cap, int audit)
{
	struct aa_profile *profile;
	/* cap_capable returns 0 on success, else -EPERM */
	int error = cap_capable(task, cred, cap, audit);

	profile = aa_cred_policy(cred);
	if (profile && (!error || cap_raised(profile->caps.set, cap)))
		error = aa_capable(task, profile, cap, audit);

	return error;
}

static int apparmor_sysctl(struct ctl_table *table, int op)
{
	int error = 0;
	struct aa_profile *profile = aa_current_profile();

	if (profile) {
		char *buffer, *name;
		int mask;

		mask = 0;
		if (op & 4)
			mask |= MAY_READ;
		if (op & 2)
			mask |= MAY_WRITE;

		error = -ENOMEM;
		/* freed below */
		buffer = (char *)__get_free_page(GFP_KERNEL);
		if (!buffer)
			goto out;

		/*
		 * TODO: convert this over to using a global or per
		 * namespace control instead of a hard coded /proc
		 */
		name = sysctl_pathname(table, buffer, PAGE_SIZE);
		if (name && name - buffer >= 5) {
			struct path_cond cond = { 0, S_IFREG };
			name -= 5;
			memcpy(name, "/proc", 5);
			error = aa_pathstr_perm(profile, "sysctl", name, mask,
						&cond);
		}
		free_page((unsigned long)buffer);
	}

out:
	return error;
}

static int common_perm(const char *op, struct path *path, u16 mask,
		       struct path_cond *cond)
{
	struct aa_profile *profile;
	int error = 0;

	profile = __aa_current_profile();
	if (profile)
		error = aa_path_perm(profile, op, path, mask, cond);

	return error;
}

static int common_perm_dentry(const char *op, struct path *dir,
			      struct dentry *dentry, u16 mask,
			      struct path_cond *cond)
{
	struct path path = { dir->mnt, dentry };

	return common_perm(op, &path, mask, cond);
}

static int common_perm_rm(const char *op, struct path *dir,
			  struct dentry *dentry, u16 mask)
{
	struct inode *inode = dentry->d_inode;
	struct path_cond cond = { };

	if (!dir->mnt || !inode || !mediated_filesystem(inode))
		return 0;

	cond.uid = inode->i_uid;
	cond.mode = inode->i_mode;

	return common_perm_dentry(op, dir, dentry, mask, &cond);
}

static int common_perm_create(const char *op, struct path *dir,
			      struct dentry *dentry, u16 mask, umode_t mode)
{
	struct path_cond cond = { current_fsuid(), mode };

	if (!dir->mnt || !mediated_filesystem(dir->dentry->d_inode))
		return 0;

	return common_perm_dentry(op, dir, dentry, mask, &cond);
}

static int apparmor_path_unlink(struct path *dir, struct dentry *dentry)
{
	return common_perm_rm("unlink", dir, dentry, MAY_WRITE);
}

static int apparmor_path_mkdir(struct path *dir, struct dentry *dentry,
			       int mode)
{
	return common_perm_create("mkdir", dir, dentry, AA_MAY_CREATE, S_IFDIR);
}

static int apparmor_path_rmdir(struct path *dir, struct dentry *dentry)
{
	return common_perm_rm("rmdir", dir, dentry, MAY_WRITE);
}

static int apparmor_path_mknod(struct path *dir, struct dentry *dentry,
			       int mode, unsigned int dev)
{
	return common_perm_create("mknod", dir, dentry, AA_MAY_CREATE, mode);
}

static int apparmor_path_truncate(struct path *path, loff_t length,
				  unsigned int time_attrs)
{
	struct path_cond cond = { path->dentry->d_inode->i_uid,
				  path->dentry->d_inode->i_mode
	};

	if (!path->mnt || !mediated_filesystem(path->dentry->d_inode))
		return 0;
	return common_perm("truncate", path, MAY_WRITE, &cond);
}

static int apparmor_path_symlink(struct path *dir, struct dentry *dentry,
				 const char *old_name)
{
	return common_perm_create("symlink_create", dir, dentry, AA_MAY_CREATE,
				  S_IFLNK);
}

static int apparmor_path_link(struct dentry *old_dentry, struct path *new_dir,
			      struct dentry *new_dentry)
{
	struct aa_profile *profile;
	int error = 0;

	if (!mediated_filesystem(old_dentry->d_inode))
		return 0;

	profile = aa_current_profile();
	if (profile)
		error = aa_path_link(profile, old_dentry, new_dir, new_dentry);
	return error;
}

static int apparmor_path_rename(struct path *old_dir, struct dentry *old_dentry,
				struct path *new_dir, struct dentry *new_dentry)
{
	struct aa_profile *profile;
	int error = 0;

	if (!mediated_filesystem(old_dentry->d_inode))
		return 0;

	profile = aa_current_profile();
	if (profile) {
		struct path old_path = { old_dir->mnt, old_dentry };
		struct path new_path = { new_dir->mnt, new_dentry };
		struct path_cond cond = { old_dentry->d_inode->i_uid,
					  old_dentry->d_inode->i_mode
		};

		error = aa_path_perm(profile, "rename_src", &old_path,
				     MAY_READ | MAY_WRITE, &cond);
		if (!error)
			error = aa_path_perm(profile, "rename_dest", &new_path,
					     AA_MAY_CREATE | MAY_WRITE, &cond);

	}
	return error;
}

static int apparmor_path_chmod(struct dentry *dentry, struct vfsmount *mnt,
			       mode_t mode)
{
	struct aa_profile *profile;
	int error = 0;

	if (!mediated_filesystem(dentry->d_inode))
		return 0;

	profile = aa_current_profile();
	if (profile) {
		struct path path = { mnt, dentry };
		struct path_cond cond = { dentry->d_inode->i_uid,
					  dentry->d_inode->i_mode
		};

		error = aa_path_perm(profile, "chmod", &path, AA_MAY_CHMOD,
			&cond);
	}

	return error;
}

static int apparmor_path_chown(struct path *path, uid_t uid, gid_t gid)
{
	struct aa_profile *profile;
	int error = 0;

	if (!mediated_filesystem(path->dentry->d_inode))
		return 0;

	profile = aa_current_profile();
	if (profile) {
		struct path_cond cond =  { path->dentry->d_inode->i_uid,
					   path->dentry->d_inode->i_mode
		};
		error = aa_path_perm(profile, "chown", path, AA_MAY_CHOWN,
				     &cond);
	}

	return error;
}

static int apparmor_dentry_open(struct file *file, const struct cred *cred)
{
	struct aa_profile *profile;
	int error = 0;

	/* If in exec, permission is handled by bprm hooks */
	if (current->in_execve ||
	    !mediated_filesystem(file->f_path.dentry->d_inode))
		return 0;

	profile = aa_cred_policy(cred);
	if (profile) {
		struct aa_file_cxt *fcxt = file->f_security;
		struct inode *inode = file->f_path.dentry->d_inode;
		struct path_cond cond = { inode->i_uid, inode->i_mode };

		error = aa_path_perm(profile, "open", &file->f_path,
				     aa_map_file_to_perms(file), &cond);
		/* released by aa_free_file_context */
		fcxt->profile = aa_get_profile(profile);
		/* todo cache actual allowed permissions */
		fcxt->allowed = 0;
	}

	return error;
}

static int apparmor_file_alloc_security(struct file *file)
{
	/* freed by apparmor_file_free_security */
	file->f_security = aa_alloc_file_context(GFP_KERNEL);
	if (!file->f_security)
		return -ENOMEM;
	return 0;

}

static void apparmor_file_free_security(struct file *file)
{
	struct aa_file_cxt *cxt = file->f_security;

	aa_free_file_context(cxt);
}

static int apparmor_file_permission(struct file *file, int mask)
{
	/*
	 * TODO: cache profiles that have revalidated?
	 */
	struct aa_file_cxt *fcxt = file->f_security;
	struct aa_profile *profile, *fprofile = fcxt->profile;
	int error = 0;

	if (!fprofile || !file->f_path.mnt ||
	    !mediated_filesystem(file->f_path.dentry->d_inode))
		return 0;

	profile = __aa_current_profile();

#ifdef CONFIG_SECURITY_APPARMOR_COMPAT_24
	/*
	 * AppArmor <= 2.4 revalidates files at access time instead
	 * of at exec.
	 */
	if (profile && ((fprofile != profile) || (mask & ~fcxt->allowed)))
		error = aa_file_perm(profile, "file_perm", file, mask);
#endif

	return error;
}

static int common_file_perm(const char *op, struct file *file, u16 mask)
{
	const struct aa_file_cxt *fcxt = file->f_security;
	struct aa_profile *profile, *fprofile = fcxt->profile;
	int error = 0;

	if (!fprofile || !file->f_path.mnt ||
	    !mediated_filesystem(file->f_path.dentry->d_inode))
		return 0;

	profile = aa_current_profile();
	if (profile && ((fprofile != profile) || (mask & ~fcxt->allowed)))
		error = aa_file_perm(profile, op, file, mask);

	return error;
}

static int apparmor_file_lock(struct file *file, unsigned int cmd)
{
	u16 mask = AA_MAY_LOCK;

	if (cmd == F_WRLCK)
		mask |= MAY_WRITE;

	return common_file_perm("file_lock", file, mask);
}

static int common_mmap(struct file *file, const char *operation,
		       unsigned long prot, unsigned long flags)
{
	struct dentry *dentry;
	int mask = 0;

	if (!file || !file->f_security)
		return 0;

	if (prot & PROT_READ)
		mask |= MAY_READ;
	/*
	 * Private mappings don't require write perms since they don't
	 * write back to the files
	 */
	if ((prot & PROT_WRITE) && !(flags & MAP_PRIVATE))
		mask |= MAY_WRITE;
	if (prot & PROT_EXEC)
		mask |= AA_EXEC_MMAP;

	dentry = file->f_path.dentry;
	return common_file_perm(operation, file, mask);
}

static int apparmor_file_mmap(struct file *file, unsigned long reqprot,
			      unsigned long prot, unsigned long flags,
			      unsigned long addr, unsigned long addr_only)
{
	int rc = 0;

	/* do DAC check */
	rc = cap_file_mmap(file, reqprot, prot, flags, addr, addr_only);
	if (rc || addr_only)
		return rc;

	return common_mmap(file, "file_mmap", prot, flags);
}

static int apparmor_file_mprotect(struct vm_area_struct *vma,
				  unsigned long reqprot, unsigned long prot)
{
	return common_mmap(vma->vm_file, "file_mprotect", prot,
			   !(vma->vm_flags & VM_SHARED) ? MAP_PRIVATE : 0);
}

static int apparmor_getprocattr(struct task_struct *task, char *name,
				char **value)
{
	int error = -ENOENT;
	struct aa_profile *profile;
	/* released below */
	const struct cred *cred = aa_get_task_cred(task, &profile);
	struct aa_task_context *cxt = cred->security;

	if (strcmp(name, "current") == 0)
		error = aa_getprocattr(cxt->sys.profile, value);
	else if (strcmp(name, "prev") == 0  && cxt->sys.previous)
		error = aa_getprocattr(cxt->sys.previous, value);
	else if (strcmp(name, "exec") == 0 && cxt->sys.onexec)
		error = aa_getprocattr(cxt->sys.onexec, value);
	else
		error = -EINVAL;

	put_cred(cred);

	return error;
}

static int apparmor_setprocattr(struct task_struct *task, char *name,
				void *value, size_t size)
{
	char *command, *args;
	int error;

	if (size == 0 || size >= PAGE_SIZE)
		return -EINVAL;

	/* task can only write its own attributes */
	if (current != task)
		return -EACCES;

	args = value;
	args[size] = '\0';
	args = strstrip(args);
	command = strsep(&args, " ");
	if (!args)
		return -EINVAL;
	while (isspace(*args))
		args++;
	if (!*args)
		return -EINVAL;

	if (strcmp(name, "current") == 0) {
		if (strcmp(command, "changehat") == 0) {
			error = aa_setprocattr_changehat(args, !AA_DO_TEST);
		} else if (strcmp(command, "permhat") == 0) {
			error = aa_setprocattr_changehat(args, AA_DO_TEST);
		} else if (strcmp(command, "changeprofile") == 0) {
			error = aa_setprocattr_changeprofile(args, 0,
							     !AA_DO_TEST);
		} else if (strcmp(command, "permprofile") == 0) {
			error = aa_setprocattr_changeprofile(args, 0,
							     AA_DO_TEST);
		} else if (strcmp(command, "permipc") == 0) {
			error = aa_setprocattr_permipc(args);
		} else {
			struct aa_audit sa = {
				.operation = "setprocattr",
				.gfp_mask = GFP_KERNEL,
				.info = name,
				.error = -EINVAL,
			};
			return aa_audit(AUDIT_APPARMOR_DENIED, NULL, &sa, NULL);
		}
	} else if (strcmp(name, "exec") == 0) {
		error = aa_setprocattr_changeprofile(strstrip(args), 1,
						     !AA_DO_TEST);
	} else {
		/* only support the "current" and "exec" process attributes */
		return -EINVAL;
	}
	if (!error)
		error = size;
	return error;
}

static int apparmor_task_setrlimit(unsigned int resource,
				   struct rlimit *new_rlim)
{
	struct aa_profile *profile = aa_current_profile();
	int error = 0;

	if (profile)
		error = aa_task_setrlimit(profile, resource, new_rlim);

	return error;
}

#ifdef CONFIG_SECURITY_APPARMOR_NETWORK
static int apparmor_socket_create(int family, int type, int protocol, int kern)
{
	struct aa_profile *profile;
	int error = 0;

	if (kern)
		return 0;

	profile = __aa_current_profile();
	if (profile)
		error = aa_net_perm(profile, "socket_create", family,
				    type, protocol);
	return error;
}

static int apparmor_socket_post_create(struct socket *sock, int family,
				       int type, int protocol, int kern)
{
	struct sock *sk = sock->sk;

	if (kern)
		return 0;

	return aa_revalidate_sk(sk, "socket_post_create");
}

static int apparmor_socket_bind(struct socket *sock,
				struct sockaddr *address, int addrlen)
{
	struct sock *sk = sock->sk;

	return aa_revalidate_sk(sk, "socket_bind");
}

static int apparmor_socket_connect(struct socket *sock,
				   struct sockaddr *address, int addrlen)
{
	struct sock *sk = sock->sk;

	return aa_revalidate_sk(sk, "socket_connect");
}

static int apparmor_socket_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;

	return aa_revalidate_sk(sk, "socket_listen");
}

static int apparmor_socket_accept(struct socket *sock, struct socket *newsock)
{
	struct sock *sk = sock->sk;

	return aa_revalidate_sk(sk, "socket_accept");
}

static int apparmor_socket_sendmsg(struct socket *sock,
				   struct msghdr *msg, int size)
{
	struct sock *sk = sock->sk;

	return aa_revalidate_sk(sk, "socket_sendmsg");
}

static int apparmor_socket_recvmsg(struct socket *sock,
				   struct msghdr *msg, int size, int flags)
{
	struct sock *sk = sock->sk;

	return aa_revalidate_sk(sk, "socket_recvmsg");
}

static int apparmor_socket_getsockname(struct socket *sock)
{
	struct sock *sk = sock->sk;

	return aa_revalidate_sk(sk, "socket_getsockname");
}

static int apparmor_socket_getpeername(struct socket *sock)
{
	struct sock *sk = sock->sk;

	return aa_revalidate_sk(sk, "socket_getpeername");
}

static int apparmor_socket_getsockopt(struct socket *sock, int level,
				      int optname)
{
	struct sock *sk = sock->sk;

	return aa_revalidate_sk(sk, "socket_getsockopt");
}

static int apparmor_socket_setsockopt(struct socket *sock, int level,
				      int optname)
{
	struct sock *sk = sock->sk;

	return aa_revalidate_sk(sk, "socket_setsockopt");
}

static int apparmor_socket_shutdown(struct socket *sock, int how)
{
	struct sock *sk = sock->sk;

	return aa_revalidate_sk(sk, "socket_shutdown");
}
#endif

static struct security_operations apparmor_ops = {
	.name =				"apparmor",

	.ptrace_access_check =		apparmor_ptrace_access_check,
	.ptrace_traceme =		apparmor_ptrace_traceme,
	.capget =			apparmor_capget,
	.sysctl =			apparmor_sysctl,
	.capable =			apparmor_capable,

	.path_link =			apparmor_path_link,
	.path_unlink =			apparmor_path_unlink,
	.path_symlink =			apparmor_path_symlink,
	.path_mkdir =			apparmor_path_mkdir,
	.path_rmdir =			apparmor_path_rmdir,
	.path_mknod =			apparmor_path_mknod,
	.path_rename =			apparmor_path_rename,
	.path_chmod =			apparmor_path_chmod,
	.path_chown =			apparmor_path_chown,
	.path_truncate =		apparmor_path_truncate,
	.dentry_open =			apparmor_dentry_open,

	.file_permission =		apparmor_file_permission,
	.file_alloc_security =		apparmor_file_alloc_security,
	.file_free_security =		apparmor_file_free_security,
	.file_mmap =			apparmor_file_mmap,
	.file_mprotect =		apparmor_file_mprotect,
	.file_lock =			apparmor_file_lock,

	.getprocattr =			apparmor_getprocattr,
	.setprocattr =			apparmor_setprocattr,

#ifdef CONFIG_SECURITY_APPARMOR_NETWORK
	.socket_create =		apparmor_socket_create,
	.socket_post_create =		apparmor_socket_post_create,
	.socket_bind =			apparmor_socket_bind,
	.socket_connect =		apparmor_socket_connect,
	.socket_listen =		apparmor_socket_listen,
	.socket_accept =		apparmor_socket_accept,
	.socket_sendmsg =		apparmor_socket_sendmsg,
	.socket_recvmsg =		apparmor_socket_recvmsg,
	.socket_getsockname =		apparmor_socket_getsockname,
	.socket_getpeername =		apparmor_socket_getpeername,
	.socket_getsockopt =		apparmor_socket_getsockopt,
	.socket_setsockopt =		apparmor_socket_setsockopt,
	.socket_shutdown =		apparmor_socket_shutdown,
#endif

	.cred_alloc_blank =		apparmor_cred_alloc_blank,
	.cred_free =			apparmor_cred_free,
	.cred_prepare =			apparmor_cred_prepare,
	.cred_transfer =		apparmor_cred_transfer,

	.bprm_set_creds =		apparmor_bprm_set_creds,
	.bprm_committing_creds =	apparmor_bprm_committing_creds,
	.bprm_committed_creds =		apparmor_bprm_committed_creds,
	.bprm_secureexec =		apparmor_bprm_secureexec,

	.task_setrlimit =		apparmor_task_setrlimit,
};

/*
 * AppArmor sysfs module parameters
 */

static int param_set_aabool(const char *val, struct kernel_param *kp);
static int param_get_aabool(char *buffer, struct kernel_param *kp);
#define param_check_aabool(name, p) __param_check(name, p, int)

static int param_set_aauint(const char *val, struct kernel_param *kp);
static int param_get_aauint(char *buffer, struct kernel_param *kp);
#define param_check_aauint(name, p) __param_check(name, p, int)

static int param_set_aalockpolicy(const char *val, struct kernel_param *kp);
static int param_get_aalockpolicy(char *buffer, struct kernel_param *kp);
#define param_check_aalockpolicy(name, p) __param_check(name, p, int)

static int param_set_audit(const char *val, struct kernel_param *kp);
static int param_get_audit(char *buffer, struct kernel_param *kp);
#define param_check_audit(name, p) __param_check(name, p, int)

static int param_set_mode(const char *val, struct kernel_param *kp);
static int param_get_mode(char *buffer, struct kernel_param *kp);
#define param_check_mode(name, p) __param_check(name, p, int)

/* Flag values, also controllable via /sys/module/apparmor/parameters
 * We define special types as we want to do additional mediation.
 */

/* AppArmor global enforcement switch - complain, enforce, kill */
enum profile_mode aa_g_profile_mode = APPARMOR_ENFORCE;
module_param_call(mode, param_set_mode, param_get_mode,
		  &aa_g_profile_mode, S_IRUSR | S_IWUSR);

/* Debug mode */
int aa_g_debug;
module_param_named(debug, aa_g_debug, aabool, S_IRUSR | S_IWUSR);

/* Audit mode */
enum audit_mode aa_g_audit;
module_param_call(audit, param_set_audit, param_get_audit,
		  &aa_g_audit, S_IRUSR | S_IWUSR);

/* Determines if audit header is included in audited messages.  This
 * provides more context if the audit daemon is not running
 */
int aa_g_audit_header;
module_param_named(audit_header, aa_g_audit_header, aabool,
		   S_IRUSR | S_IWUSR);

/* lock out loading/removal of policy
 * TODO: add in at boot loading of policy, which is the only way to
 *       load policy, if lock_policy is set
 */
int aa_g_lock_policy;
module_param_named(lock_policy, aa_g_lock_policy, aalockpolicy,
		   S_IRUSR | S_IWUSR);

/* Syscall logging mode */
int aa_g_logsyscall;
module_param_named(logsyscall, aa_g_logsyscall, aabool, S_IRUSR | S_IWUSR);

/* Maximum pathname length before accesses will start getting rejected */
unsigned int aa_g_path_max = 2 * PATH_MAX;
module_param_named(path_max, aa_g_path_max, aauint, S_IRUSR | S_IWUSR);

/* Determines how paranoid loading of policy is and how much verification
 * on the loaded policy is done.
 */
int aa_g_paranoid_load = 1;
module_param_named(paranoid_load, aa_g_paranoid_load, aabool,
		   S_IRUSR | S_IWUSR);

/* Boot time disable flag */
#ifdef CONFIG_SECURITY_APPARMOR_DISABLE
#define AA_ENABLED_PERMS 0600
#else
#define AA_ENABLED_PERMS 0400
#endif
static int param_set_aa_enabled(const char *val, struct kernel_param *kp);
static unsigned int apparmor_enabled = CONFIG_SECURITY_APPARMOR_BOOTPARAM_VALUE;
module_param_call(enabled, param_set_aa_enabled, param_get_aauint,
		  &apparmor_enabled, AA_ENABLED_PERMS);

static int __init apparmor_enabled_setup(char *str)
{
	unsigned long enabled;
	int error = strict_strtoul(str, 0, &enabled);
	if (!error)
		apparmor_enabled = enabled ? 1 : 0;
	return 1;
}

__setup("apparmor=", apparmor_enabled_setup);

/* set global flag turning off the ability to load policy */
static int param_set_aalockpolicy(const char *val, struct kernel_param *kp)
{
	if (!capable(CAP_MAC_ADMIN))
		return -EPERM;
	if (aa_g_lock_policy)
		return -EACCES;
	return param_set_bool(val, kp);
}

static int param_get_aalockpolicy(char *buffer, struct kernel_param *kp)
{
	if (!capable(CAP_MAC_ADMIN))
		return -EPERM;
	return param_get_bool(buffer, kp);
}

static int param_set_aabool(const char *val, struct kernel_param *kp)
{
	if (!capable(CAP_MAC_ADMIN))
		return -EPERM;
	return param_set_bool(val, kp);
}

static int param_get_aabool(char *buffer, struct kernel_param *kp)
{
	if (!capable(CAP_MAC_ADMIN))
		return -EPERM;
	return param_get_bool(buffer, kp);
}

static int param_set_aauint(const char *val, struct kernel_param *kp)
{
	if (!capable(CAP_MAC_ADMIN))
		return -EPERM;
	return param_set_uint(val, kp);
}

static int param_get_aauint(char *buffer, struct kernel_param *kp)
{
	if (!capable(CAP_MAC_ADMIN))
		return -EPERM;
	return param_get_uint(buffer, kp);
}

/* allow run time disabling of apparmor */
static int param_set_aa_enabled(const char *val, struct kernel_param *kp)
{
	unsigned long l;

	if (!apparmor_initialized) {
		apparmor_enabled = 0;
		return 0;
	}

	if (!capable(CAP_MAC_ADMIN))
		return -EPERM;

	if (!apparmor_enabled)
		return -EINVAL;

	if (!val)
		return -EINVAL;

	if (strict_strtoul(val, 0, &l) || l != 0)
		return -EINVAL;

	apparmor_enabled = 0;
	apparmor_disable();
	return 0;
}

static int param_get_audit(char *buffer, struct kernel_param *kp)
{
	if (!capable(CAP_MAC_ADMIN))
		return -EPERM;

	if (!apparmor_enabled)
		return -EINVAL;

	return sprintf(buffer, "%s", audit_mode_names[aa_g_audit]);
}

static int param_set_audit(const char *val, struct kernel_param *kp)
{
	int i;
	if (!capable(CAP_MAC_ADMIN))
		return -EPERM;

	if (!apparmor_enabled)
		return -EINVAL;

	if (!val)
		return -EINVAL;

	for (i = 0; i < AUDIT_MAX_INDEX; i++) {
		if (strcmp(val, audit_mode_names[i]) == 0) {
			aa_g_audit = i;
			return 0;
		}
	}

	return -EINVAL;
}

static int param_get_mode(char *buffer, struct kernel_param *kp)
{
	if (!capable(CAP_MAC_ADMIN))
		return -EPERM;

	if (!apparmor_enabled)
		return -EINVAL;

	return sprintf(buffer, "%s", profile_mode_names[aa_g_profile_mode]);
}

static int param_set_mode(const char *val, struct kernel_param *kp)
{
	int i;
	if (!capable(CAP_MAC_ADMIN))
		return -EPERM;

	if (!apparmor_enabled)
		return -EINVAL;

	if (!val)
		return -EINVAL;

	for (i = 0; i < APPARMOR_NAMES_MAX_INDEX; i++) {
		if (strcmp(val, profile_mode_names[i]) == 0) {
			aa_g_profile_mode = i;
			return 0;
		}
	}

	return -EINVAL;
}

/*
 * AppArmor init functions
 */
static int __init set_init_cxt(void)
{
	struct cred *cred = (struct cred *)current->real_cred;
	struct aa_task_context *cxt;

	cxt = aa_alloc_task_context(GFP_KERNEL);
	if (!cxt)
		return -ENOMEM;

	cxt->sys.profile = aa_get_profile(default_namespace->unconfined);
	cred->security = cxt;

	return 0;
}

static int __init apparmor_init(void)
{
	int error;

	if (!apparmor_enabled || !security_module_enable(&apparmor_ops)) {
		aa_info_message("AppArmor disabled by boot time parameter\n");
		apparmor_enabled = 0;
		return 0;
	}

	error = aa_alloc_default_namespace();
	if (error) {
		AA_ERROR("Unable to allocate default profile namespace\n");
		goto alloc_out;
	}

	error = set_init_cxt();
	if (error) {
		AA_ERROR("Failed to set context on init task\n");
		goto register_security_out;
	}

	error = register_security(&apparmor_ops);
	if (error) {
		AA_ERROR("Unable to register AppArmor\n");
		goto register_security_out;
	}

	/* Report that AppArmor successfully initialized */
	apparmor_initialized = 1;
	if (aa_g_profile_mode == APPARMOR_COMPLAIN)
		aa_info_message("AppArmor initialized: complain mode enabled");
	else if (aa_g_profile_mode == APPARMOR_KILL)
		aa_info_message("AppArmor initialized: kill mode enabled");
	else
		aa_info_message("AppArmor initialized");

	return error;

register_security_out:
	aa_free_default_namespace();

alloc_out:
	aa_destroy_aafs();

	apparmor_enabled = 0;
	return error;

}

security_initcall(apparmor_init);

void apparmor_disable(void)
{
	/* Remove and release all the profiles on the profile list. */
	aa_profile_ns_list_release();

	/* FIXME: cleanup profiles references on files */
	aa_free_default_namespace();

	aa_destroy_aafs();
	apparmor_initialized = 0;

	aa_info_message("AppArmor protection disabled");
}
