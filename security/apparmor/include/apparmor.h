/*
 * AppArmor security module
 *
 * This file contains AppArmor basic global and lib definitions
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2010 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#ifndef __APPARMOR_H
#define __APPARMOR_H

#include <linux/fs.h>

#include "match.h"

/* Control parameters settable thru module/boot flags or
 * via /sys/kernel/security/apparmor/control */
extern enum audit_mode aa_g_audit;
extern int aa_g_audit_header;
extern int aa_g_debug;
extern int aa_g_lock_policy;
extern int aa_g_logsyscall;
extern int aa_g_paranoid_load;
extern unsigned int aa_g_path_max;

/*
 * DEBUG remains global (no per profile flag) since it is mostly used in sysctl
 * which is not related to profile accesses.
 */

#define AA_DEBUG(fmt, args...)						\
	do {								\
		if (aa_g_debug && printk_ratelimit())			\
			printk(KERN_DEBUG "AppArmor: " fmt, ##args);	\
	} while (0)

#define AA_ERROR(fmt, args...)						\
	do {								\
		if (printk_ratelimit())					\
			printk(KERN_ERR "AppArmor: " fmt, ##args);	\
	} while (0)

/* Flag indicating whether initialization completed */
extern int apparmor_initialized;
void apparmor_disable(void);

/* fn's in lib */
char *aa_split_fqname(char *args, char **ns_name);
bool aa_strneq(const char *str, const char *sub, int len);
void aa_info_message(const char *str);

/**
 * aa_dfa_null_transition - step to next state after null character
 * @dfa: the dfa to match against
 * @start: the state of the dfa to start matching in
 * @old: true if using // as the null transition
 *
 * aa_dfa_null_transition transitions to the next state after a null
 * character which is not used in standard matching and is only
 * used to seperate pairs.
 */
static inline unsigned int aa_dfa_null_transition(struct aa_dfa *dfa,
						  unsigned int start, bool old)
{
	if (unlikely(old))
		return aa_dfa_match_len(dfa, start, "//", 2);
	else
		return aa_dfa_match_len(dfa, start, "\0", 1);
}

static inline bool mediated_filesystem(struct inode *inode)
{
	return !(inode->i_sb->s_flags & MS_NOUSER);
}

#endif /* __APPARMOR_H */
