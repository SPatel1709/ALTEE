/*
	Definitions for ABAC Securityfs structures and methods
	Copyright (C) <2021>  Hariyala Omkara Naga Sai Varshith
*/

#ifndef _ABAC_FS_H_
#define _ABAC_FS_H_

#include "avp.h"
#include "env.h"
#include "obj.h"
#include "policy.h"
#include "user.h"
#include <linux/types.h>

/* Pointer to the abac policy. Initialized in abacfs */
extern abac_policy *policy;

/* Pointer to the user attribute list. Initialized in abacfs */
extern abac_user *user_attr;

/* Pointer to the object attribute list. Initialized in abacfs */
extern abac_obj *obj_attr;

/* Pointer to the environment attribute list. Initialized in abacfs */
extern avp *env_attr;

enum abac_resolve_mode { ABAC_RESOLVE_LINEAR, ABAC_RESOLVE_TREE };
enum abac_tee_mode { ABAC_TEE_OFF, ABAC_TEE_ON };

struct abac_perf_stats {
	u64 total_time_ns;
	u64 min_time_ns;
	u64 max_time_ns;
	u64 decision_count;
	u64 allow_count;
	u64 deny_count;
	u64 prev_access_time_ns;
};

struct abac_path_entry {
	char *path;
	struct abac_path_entry *next;
};

extern enum abac_resolve_mode abac_mode;
extern enum abac_tee_mode abac_tee_mode;
extern bool abac_use_hashmap;
extern int abac_recording;
extern struct abac_perf_stats abac_stats;
extern struct abac_path_entry *abac_include_paths;
extern struct abac_path_entry *abac_exclude_paths;

void abac_reset_perf_stats(void);
void abac_record_decision(u64 elapsed_ns, bool allowed);
bool abac_path_is_covered(const char *path);

#endif /* _ABAC_FS_H */
