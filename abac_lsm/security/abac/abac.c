/*
	ABAC LSM hooks
	Copyright (C) <2021>  Hariyala Omkara Naga Sai Varshith
*/

#include <linux/limits.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/binfmts.h>
#include <linux/xattr.h>
#include <linux/kernel_read_file.h>
#include <linux/lsm_hooks.h>
#include <linux/dcache.h>
#include <linux/cred.h>
#include <linux/slab.h>
#include <linux/timekeeping.h>
#include <linux/err.h>
#include "abacfs.h"
#include "resolve.h"

// get full filename
char *get_full_name(struct file *file, char *buf, int buflen)
{
	char *ret = d_path(&file->f_path, buf, buflen);
	return ret;
}

// File read/write hook
static int abac_file_permission(struct file *file, int mask)
{
	u64 start_ns, elapsed_ns;
	bool allowed;
	// if the user is root, don't evaluate
	unsigned int UID = current_uid().val;
	if (UID < 1000) {
		return 0;
	}
	char *path = NULL;
	char *buff = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buff)
		return -ENOMEM;
	path = d_path(&file->f_path, buff, PATH_MAX);
	if (IS_ERR(path)) {
		int err = PTR_ERR(path);
		kfree(buff);
		return err;
	}
	// if the path is not secured, don't evaluate
	if (!abac_path_is_covered(path)) {
		kfree(buff);
		return 0;
	}
	// if the policy is not yet initalized, DENY permission
	if (policy == NULL || user_attr == NULL || obj_attr == NULL) {
		kfree(buff);
		return -EPERM;
	}
	start_ns = abac_recording ? ktime_get_ns() : 0;
	allowed = abac_resolve(UID, path, mask);
	if (abac_recording) {
		elapsed_ns = ktime_get_ns() - start_ns;
		abac_record_decision(elapsed_ns, allowed);
	}
	kfree(buff);
	if (allowed) {
		return 0;
	}
	return -EPERM;
}

// The hooks we wish to be installed.
static struct lsm_id abac_lsmid __ro_after_init = {
	.name = "abac",
};

// At Checkpoint file_permission invoke abac_file_permission function.
static struct security_hook_list abac_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(file_permission, abac_file_permission),
};

// Initialize our module.
static int __init abac_init(void)
{
	security_add_hooks(abac_hooks, ARRAY_SIZE(abac_hooks), &abac_lsmid);
	printk(KERN_INFO
	       "ABAC LSM: Initialized.\n Protected files are selected by ABAC include/exclude path rules.\n");
	return 0;
}
DEFINE_LSM(abac) = {
	.init = abac_init,
	.name = "abac",
};
