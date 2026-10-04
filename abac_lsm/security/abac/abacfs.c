/*
	ABAC securityFS system calls
	Copyright (C) <2021>  Hariyala Omkara Naga Sai Varshith
*/

#include "abacfs.h"
#include "pathcfg.h"
#include "resolve.h"
#include "tee_bridge.h"
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>

// const size_t MAX_FILE_SIZE = 65536; // 64Kb
const size_t MAX_FILE_SIZE = 16777216; // 16MB

struct dentry *abacfs;
struct dentry *policy_file;
struct dentry *user_attr_file;
struct dentry *obj_attr_file;
struct dentry *env_attr_file;
struct dentry *action_file;
struct dentry *perf_file;
struct dentry *stats_file;
struct dentry *mode_file;
struct dentry *tee_mode_file;
struct dentry *tee_request_file;
struct dentry *tee_response_file;
struct dentry *tee_policy_file;
struct dentry *hashmap_file;
struct dentry *include_paths_file;
struct dentry *exclude_paths_file;

char *policy_buf = NULL;
char *user_attr_buf = NULL;
char *obj_attr_buf = NULL;
char *env_attr_buf = NULL;
char *include_paths_buf = NULL;
char *exclude_paths_buf = NULL;

abac_policy *policy = NULL;
abac_user *user_attr = NULL;
abac_obj *obj_attr = NULL;
avp *env_attr = NULL;
enum abac_resolve_mode abac_mode = ABAC_RESOLVE_TREE;
enum abac_tee_mode abac_tee_mode = ABAC_TEE_OFF;
bool abac_use_hashmap;
int abac_recording;
struct abac_perf_stats abac_stats;
struct abac_path_entry *abac_include_paths = NULL;
struct abac_path_entry *abac_exclude_paths = NULL;

void abac_reset_perf_stats(void)
{
	memset(&abac_stats, 0, sizeof(abac_stats));
}

void abac_record_decision(u64 elapsed_ns, bool allowed)
{
	abac_stats.prev_access_time_ns = elapsed_ns;
	abac_stats.total_time_ns += elapsed_ns;
	abac_stats.decision_count++;
	if (abac_stats.min_time_ns == 0 || elapsed_ns < abac_stats.min_time_ns)
		abac_stats.min_time_ns = elapsed_ns;
	if (elapsed_ns > abac_stats.max_time_ns)
		abac_stats.max_time_ns = elapsed_ns;
	if (allowed)
		abac_stats.allow_count++;
	else
		abac_stats.deny_count++;
}

bool abac_path_is_covered(const char *path)
{
        if (!path || path[0] != '/')
                return false;

        /* No configured scope means ABAC is not ready to enforce yet. */
        if (!abac_include_paths)
                return false;
        if (!path_matches_entries(path, abac_include_paths))
                return false;

        if (abac_exclude_paths &&
            path_matches_entries(path, abac_exclude_paths))
                return false;

        return true;
}

// method for opening policy file
static int abac_open(struct inode *i, struct file *f)
{
	// TODO: Add a check to let only the root access the policy file
	return 0;
}

// method for writing to policy file
static ssize_t policy_write(struct file *filp, const char __user *buffer,
			    size_t len, loff_t *off)
{
	if (len >= MAX_FILE_SIZE) {
		printk(KERN_INFO
		       "Write failed. Buffer too large %zu. Maximum Policy file size is %zu\n",
		       len, MAX_FILE_SIZE);
		return -EFAULT;
	}
	if (policy_buf) {
		destroy_policy(policy);
		kfree(policy_buf);
	}
	policy_buf = kmalloc(len + 1, GFP_KERNEL);
	if (!policy_buf) {
		printk(KERN_INFO
		       "Write failed. Failed to allocate memory for policy buffer\n");
		return -EFAULT;
	}
	if (copy_from_user(policy_buf, buffer, len)) {
		printk(KERN_INFO "Write to policy failed\n");
		return -EFAULT;
	}
	policy_buf[len] = '\0';
	printk("Policy written to buffer. Attempting to parse...");
	policy = parse_policy(policy_buf, len);
	// print_abac_policy(policy);
	printk("Policy loaded");
	return len;
}

// method for reading from policy file
static ssize_t policy_read(struct file *filp, char __user *buffer, size_t len,
			   loff_t *off)
{
	if (!policy_buf) {
		return -EFAULT;
	}
	/*
static int finished = 0;
if (finished) {
    finished = 0;
    return 0;
}
finished = 1;
*/

	int policy_buf_len = strlen(policy_buf);
	if (copy_to_user(buffer, policy_buf, policy_buf_len) != 0) {
		printk(KERN_INFO "Read from policy failed\n");
		return -EFAULT;
	}
	// Return the number of bytes read
	return policy_buf_len;
}

// method for writing to user_attrs file
static ssize_t user_attr_write(struct file *filp, const char __user *buffer,
			       size_t len, loff_t *off)
{
	if (len >= MAX_FILE_SIZE) {
		printk(KERN_INFO
		       "Write failed. Buffer too large %zu. Maximum file size is %zu\n",
		       len, MAX_FILE_SIZE);
		return -EFAULT;
	}
	if (user_attr_buf) {
		abac_destroy_lookup_maps();
		destroy_user_list(user_attr);
		kfree(user_attr_buf);
	}
	user_attr_buf = kmalloc(len + 1, GFP_KERNEL);
	if (!user_attr_buf) {
		printk(KERN_INFO
		       "Write failed. Failed to allocate memory for user attributes buffer\n");
		return -EFAULT;
	}
	if (copy_from_user(user_attr_buf, buffer, len)) {
		printk(KERN_INFO "Write to user_attrs failed\n");
		return -EFAULT;
	}
	user_attr_buf[len] = '\0';
	printk("User attributes written to buffer. Attempting to parse...");
	user_attr = parse_user_attr(user_attr_buf, len);
	abac_rebuild_lookup_maps();
	//print_user_attrs(user_attr);
	printk("User attributes loaded");
	return len;
}

// method for writing to obj_attrs file
static ssize_t obj_attr_write(struct file *filp, const char __user *buffer,
			      size_t len, loff_t *off)
{
	if (len >= MAX_FILE_SIZE) {
		printk(KERN_INFO
		       "Write failed. Buffer too large %zu. Maximum file size is %zu\n",
		       len, MAX_FILE_SIZE);
		return -EFAULT;
	}
	if (obj_attr_buf) {
		abac_destroy_lookup_maps();
		destroy_obj_list(obj_attr);
		kfree(obj_attr_buf);
	}
	obj_attr_buf = kmalloc(len + 1, GFP_KERNEL);
	if (!obj_attr_buf) {
		printk(KERN_INFO
		       "Write failed. Failed to allocate memory for object "
		       "attributes buffer\n");
		return -EFAULT;
	}
	if (copy_from_user(obj_attr_buf, buffer, len)) {
		printk(KERN_INFO "Write to obj_attrs failed\n");
		return -EFAULT;
	}
	obj_attr_buf[len] = '\0';
	printk("Object attributes written to buffer. Attempting to parse...");
	obj_attr = parse_obj_attr(obj_attr_buf, len);
	abac_rebuild_lookup_maps();
	//print_obj_attrs(obj_attr);
	printk("Object attributes loaded");
	return len;
}

// method for writing to env_attrs file
static ssize_t env_attr_write(struct file *filp, const char __user *buffer,
			      size_t len, loff_t *off)
{
	if (len >= MAX_FILE_SIZE) {
		printk(KERN_INFO
		       "Write failed. Buffer too large %zu. Maximum file size is %zu\n",
		       len, MAX_FILE_SIZE);
		return -EFAULT;
	}
	if (env_attr_buf) {
		destroy_avp_list(env_attr);
		kfree(env_attr_buf);
	}
	env_attr_buf = kmalloc(len + 1, GFP_KERNEL);
	if (!env_attr_buf) {
		printk(KERN_INFO
		       "Write failed. Failed to allocate memory for environment "
		       "attributes buffer\n");
		return -EFAULT;
	}
	if (copy_from_user(env_attr_buf, buffer, len)) {
		printk(KERN_INFO "Write to env_attrs failed\n");
		return -EFAULT;
	}
	env_attr_buf[len] = '\0';
	printk("Environment attributes written to buffer. Attempting to parse...");
	env_attr = parse_env_attr(env_attr_buf, len);
	//print_env_attrs(env_attr);
	printk("Environment attributes loaded");
	return len;
}

static const struct file_operations policy_fops = {
	.open = abac_open,
	.read = policy_read,
	.write = policy_write,
};

static const struct file_operations user_attr_fops = {
	.open = abac_open,
	.write = user_attr_write,
};

static const struct file_operations obj_attr_fops = {
	.open = abac_open,
	.write = obj_attr_write,
};

static const struct file_operations env_attr_fops = {
	.open = abac_open,
	.write = env_attr_write,
};

static ssize_t include_paths_write(struct file *filp,
				   const char __user *buffer,
				   size_t len, loff_t *off)
{
	if (len >= MAX_FILE_SIZE)
		return -EFAULT;
	if (include_paths_buf) {
		destroy_path_entries(abac_include_paths);
		kfree(include_paths_buf);
		abac_include_paths = NULL;
	}
	include_paths_buf = kmalloc(len + 1, GFP_KERNEL);
	if (!include_paths_buf)
		return -EFAULT;
	if (copy_from_user(include_paths_buf, buffer, len))
		return -EFAULT;
	include_paths_buf[len] = '\0';
	abac_include_paths = parse_path_entries(include_paths_buf, len);
	return len;
}

static ssize_t exclude_paths_write(struct file *filp,
				   const char __user *buffer,
				   size_t len, loff_t *off)
{
	if (len >= MAX_FILE_SIZE)
		return -EFAULT;
	if (exclude_paths_buf) {
		destroy_path_entries(abac_exclude_paths);
		kfree(exclude_paths_buf);
		abac_exclude_paths = NULL;
	}
	exclude_paths_buf = kmalloc(len + 1, GFP_KERNEL);
	if (!exclude_paths_buf)
		return -EFAULT;
	if (copy_from_user(exclude_paths_buf, buffer, len))
		return -EFAULT;
	exclude_paths_buf[len] = '\0';
	abac_exclude_paths = parse_path_entries(exclude_paths_buf, len);
	return len;
}

static ssize_t include_paths_read(struct file *filp, char __user *buffer,
				  size_t len, loff_t *off)
{
	if (!include_paths_buf)
		return 0;
	return simple_read_from_buffer(buffer, len, off, include_paths_buf,
				       strlen(include_paths_buf));
}

static ssize_t exclude_paths_read(struct file *filp, char __user *buffer,
				  size_t len, loff_t *off)
{
	if (!exclude_paths_buf)
		return 0;
	return simple_read_from_buffer(buffer, len, off, exclude_paths_buf,
				       strlen(exclude_paths_buf));
}

static ssize_t action_write(struct file *filp, const char __user *buffer,
			    size_t len, loff_t *off)
{
	char cmd[32];
	size_t copy_len = min(len, sizeof(cmd) - 1);

	if (copy_from_user(cmd, buffer, copy_len))
		return -EFAULT;
	cmd[copy_len] = '\0';
	if (copy_len > 0 && cmd[copy_len - 1] == '\n')
		cmd[copy_len - 1] = '\0';

	if (strcmp(cmd, "RECORD") == 0) {
		abac_recording = 1;
		return len;
	}
	if (strcmp(cmd, "STOP") == 0) {
		abac_recording = 0;
		return len;
	}
	if (strcmp(cmd, "RESET") == 0) {
		abac_reset_perf_stats();
		return len;
	}
	return -EINVAL;
}

static ssize_t perf_read(struct file *filp, char __user *buffer, size_t len,
			 loff_t *off)
{
	char out[32];
	int out_len;

	out_len = scnprintf(out, sizeof(out), "%llu\n",
			    abac_stats.prev_access_time_ns);
	return simple_read_from_buffer(buffer, len, off, out, out_len);
}

static ssize_t stats_read(struct file *filp, char __user *buffer, size_t len,
			  loff_t *off)
{
	char out[256];
	int out_len;

	out_len = scnprintf(out, sizeof(out),
			    "decision_count=%llu\nallow_count=%llu\ndeny_count=%llu\ntotal_time_ns=%llu\nmin_time_ns=%llu\nmax_time_ns=%llu\nprev_access_time_ns=%llu\n",
			    abac_stats.decision_count, abac_stats.allow_count,
			    abac_stats.deny_count, abac_stats.total_time_ns,
			    abac_stats.min_time_ns, abac_stats.max_time_ns,
			    abac_stats.prev_access_time_ns);
	return simple_read_from_buffer(buffer, len, off, out, out_len);
}

static ssize_t mode_read(struct file *filp, char __user *buffer, size_t len,
			 loff_t *off)
{
	const char *mode = abac_mode == ABAC_RESOLVE_LINEAR ? "linear\n" :
							      "tree\n";
	return simple_read_from_buffer(buffer, len, off, mode, strlen(mode));
}

static ssize_t mode_write(struct file *filp, const char __user *buffer,
			  size_t len, loff_t *off)
{
	char mode[16];
	size_t copy_len = min(len, sizeof(mode) - 1);

	if (copy_from_user(mode, buffer, copy_len))
		return -EFAULT;
	mode[copy_len] = '\0';
	if (copy_len > 0 && mode[copy_len - 1] == '\n')
		mode[copy_len - 1] = '\0';

	if (strcmp(mode, "linear") == 0) {
		abac_mode = ABAC_RESOLVE_LINEAR;
		return len;
	}
	if (strcmp(mode, "tree") == 0) {
                if (abac_tee_mode == ABAC_TEE_ON)
                        return -EINVAL;
                abac_mode = ABAC_RESOLVE_TREE;
                return len;
        }
	return -EINVAL;
}

static const struct file_operations action_fops = {
	.open = abac_open,
	.write = action_write,
};

static const struct file_operations perf_fops = {
	.open = abac_open,
	.read = perf_read,
};

static const struct file_operations stats_fops = {
	.open = abac_open,
	.read = stats_read,
};

static const struct file_operations mode_fops = {
	.open = abac_open,
	.read = mode_read,
	.write = mode_write,
};

static ssize_t tee_mode_read(struct file *filp, char __user *buffer,
                             size_t len, loff_t *off)
{
        const char *state = abac_tee_mode == ABAC_TEE_ON ? "on\n" : "off\n";

        return simple_read_from_buffer(buffer, len, off, state, strlen(state));
}

static ssize_t tee_mode_write(struct file *filp, const char __user *buffer,
                              size_t len, loff_t *off)
{
        char state[16];
        size_t copy_len = min(len, sizeof(state) - 1);

        if (copy_from_user(state, buffer, copy_len))
                return -EFAULT;
        state[copy_len] = '\0';
        if (copy_len > 0 && state[copy_len - 1] == '\n')
                state[copy_len - 1] = '\0';

        if (strcmp(state, "on") == 0) {
                abac_tee_mode = ABAC_TEE_ON;
                abac_mode = ABAC_RESOLVE_LINEAR;
                return len;
        }
        if (strcmp(state, "off") == 0) {
                abac_tee_mode = ABAC_TEE_OFF;
                return len;
        }
        return -EINVAL;
}

static const struct file_operations tee_mode_fops = {
        .open = abac_open,
        .read = tee_mode_read,
        .write = tee_mode_write,
};

static ssize_t hashmap_read(struct file *filp, char __user *buffer, size_t len,
			    loff_t *off)
{
	const char *state = abac_use_hashmap ? "on\n" : "off\n";

	return simple_read_from_buffer(buffer, len, off, state, strlen(state));
}

static ssize_t hashmap_write(struct file *filp, const char __user *buffer,
			     size_t len, loff_t *off)
{
	char state[16];
	size_t copy_len = min(len, sizeof(state) - 1);

	if (copy_from_user(state, buffer, copy_len))
		return -EFAULT;
	state[copy_len] = '\0';
	if (copy_len > 0 && state[copy_len - 1] == '\n')
		state[copy_len - 1] = '\0';

	if (strcmp(state, "on") == 0 || strcmp(state, "1") == 0 ||
	    strcmp(state, "enabled") == 0) {
		abac_use_hashmap = true;
		return len;
	}
	if (strcmp(state, "off") == 0 || strcmp(state, "0") == 0 ||
	    strcmp(state, "disabled") == 0) {
		abac_use_hashmap = false;
		return len;
	}
	return -EINVAL;
}

static const struct file_operations hashmap_fops = {
	.open = abac_open,
	.read = hashmap_read,
	.write = hashmap_write,
};

static const struct file_operations include_paths_fops = {
	.open = abac_open,
	.read = include_paths_read,
	.write = include_paths_write,
};

static const struct file_operations exclude_paths_fops = {
	.open = abac_open,
	.read = exclude_paths_read,
	.write = exclude_paths_write,
};

static void destroy_abac_fs(void)
{
	if (policy_file) {
		securityfs_remove(policy_file);
	}
	if (user_attr_file) {
		securityfs_remove(user_attr_file);
	}
	if (obj_attr_file) {
		securityfs_remove(obj_attr_file);
	}
	if (env_attr_file) {
		securityfs_remove(env_attr_file);
	}
	if (action_file) {
		securityfs_remove(action_file);
	}
	if (perf_file) {
		securityfs_remove(perf_file);
	}
	if (stats_file) {
		securityfs_remove(stats_file);
	}
	if (mode_file) {
		securityfs_remove(mode_file);
	}
        if (tee_mode_file) {
                securityfs_remove(tee_mode_file);
        }
        if (tee_policy_file)
                securityfs_remove(tee_policy_file);
        if (tee_response_file)
                securityfs_remove(tee_response_file);
        if (tee_request_file)
                securityfs_remove(tee_request_file);
	if (hashmap_file) {
		securityfs_remove(hashmap_file);
	}
	if (include_paths_file) {
		securityfs_remove(include_paths_file);
	}
	if (exclude_paths_file) {
		securityfs_remove(exclude_paths_file);
	}
	if (abacfs) {
		securityfs_remove(abacfs);
	}
}

/* create the abac filesystem */
static int __init abac_create_fs(void)
{
	// create the root 'abac' directory
	abacfs = securityfs_create_dir("abac", NULL);
	if (!abacfs) {
		printk(KERN_ERR "ABAC LSM: Failed to create abac securityfs "
				"/sys/kernel/security/abac/");
		destroy_abac_fs();
	}

	// create the policy file
	policy_file = securityfs_create_file("policy", 0600, abacfs, NULL,
					     &policy_fops);
	if (!policy_file) {
		printk(KERN_ERR
		       "ABAC LSM: Failed to create file /sys/kernel/security/abac/policy");
		destroy_abac_fs();
		return -ENOMEM;
	}
	printk(KERN_INFO
	       "ABAC LSM: Created file /sys/kernel/security/abac/policy");

	// create the user attributes file
	user_attr_file = securityfs_create_file("user_attr", 0600, abacfs, NULL,
						&user_attr_fops);
	if (!user_attr_file) {
		printk(KERN_ERR
		       "ABAC LSM: Failed to create file /sys/kernel/security/abac/user_attr");
		destroy_abac_fs();
		return -ENOMEM;
	}
	printk(KERN_INFO
	       "ABAC LSM: Created file /sys/kernel/security/abac/user_attr");

	// create the object attributes file
	obj_attr_file = securityfs_create_file("obj_attr", 0600, abacfs, NULL,
					       &obj_attr_fops);
	if (!obj_attr_file) {
		printk(KERN_ERR
		       "ABAC LSM: Failed to create file /sys/kernel/security/abac/obj_attr");
		destroy_abac_fs();
		return -ENOMEM;
	}
	printk(KERN_INFO
	       "ABAC LSM: Created file /sys/kernel/security/abac/obj_attr");

	// create the environment attributes file
	env_attr_file = securityfs_create_file("env_attr", 0600, abacfs, NULL,
					       &env_attr_fops);
	if (!env_attr_file) {
		printk(KERN_ERR
		       "ABAC LSM: Failed to create file /sys/kernel/security/abac/env_attr");
		destroy_abac_fs();
		return -ENOMEM;
	}
	printk(KERN_INFO
	       "ABAC LSM: Created file /sys/kernel/security/abac/env_attr");

	action_file = securityfs_create_file("action", 0600, abacfs, NULL,
					     &action_fops);
	if (!action_file) {
		printk(KERN_ERR
		       "ABAC LSM: Failed to create file /sys/kernel/security/abac/action");
		destroy_abac_fs();
		return -ENOMEM;
	}
	printk(KERN_INFO
	       "ABAC LSM: Created file /sys/kernel/security/abac/action");

	perf_file = securityfs_create_file("perf", 0444, abacfs, NULL,
					   &perf_fops);
	if (!perf_file) {
		printk(KERN_ERR
		       "ABAC LSM: Failed to create file /sys/kernel/security/abac/perf");
		destroy_abac_fs();
		return -ENOMEM;
	}
	printk(KERN_INFO
	       "ABAC LSM: Created file /sys/kernel/security/abac/perf");

	stats_file = securityfs_create_file("stats", 0444, abacfs, NULL,
					    &stats_fops);
	if (!stats_file) {
		printk(KERN_ERR
		       "ABAC LSM: Failed to create file /sys/kernel/security/abac/stats");
		destroy_abac_fs();
		return -ENOMEM;
	}
	printk(KERN_INFO
	       "ABAC LSM: Created file /sys/kernel/security/abac/stats");

	mode_file = securityfs_create_file("mode", 0600, abacfs, NULL,
					   &mode_fops);
	if (!mode_file) {
		printk(KERN_ERR
		       "ABAC LSM: Failed to create file /sys/kernel/security/abac/mode");
		destroy_abac_fs();
		return -ENOMEM;
	}
	printk(KERN_INFO
	       "ABAC LSM: Created file /sys/kernel/security/abac/mode");

        tee_mode_file = securityfs_create_file("tee_mode", 0600, abacfs,
                                               NULL, &tee_mode_fops);
        if (!tee_mode_file) {
                printk(KERN_ERR
                       "ABAC LSM: Failed to create file /sys/kernel/security/abac/tee_mode");
                destroy_abac_fs();
                return -ENOMEM;
        }
        printk(KERN_INFO
               "ABAC LSM: Created file /sys/kernel/security/abac/tee_mode");

        tee_request_file = securityfs_create_file(
                "tee_request", 0400, abacfs, NULL,
                &abac_tee_request_fops);
        if (IS_ERR(tee_request_file)) {
                tee_request_file = NULL;
                destroy_abac_fs();
                return -ENOMEM;
        }

        tee_response_file = securityfs_create_file(
                "tee_response", 0200, abacfs, NULL,
                &abac_tee_response_fops);
        if (IS_ERR(tee_response_file)) {
                tee_response_file = NULL;
                destroy_abac_fs();
                return -ENOMEM;
        }

        printk(KERN_INFO
               "ABAC LSM: Created TEE request/response files");

        tee_policy_file = securityfs_create_file("tee_policy", 0600, abacfs, NULL,
                                                  &abac_tee_policy_fops);
        if (IS_ERR(tee_policy_file)) {
                tee_policy_file = NULL;
                destroy_abac_fs();
                return -ENOMEM;
        }

        printk(KERN_INFO
               "ABAC LSM: Created file /sys/kernel/security/abac/tee_policy");

	hashmap_file = securityfs_create_file("hashmap", 0600, abacfs, NULL,
					      &hashmap_fops);
	if (!hashmap_file) {
		printk(KERN_ERR
		       "ABAC LSM: Failed to create file /sys/kernel/security/abac/hashmap");
		destroy_abac_fs();
		return -ENOMEM;
	}
	printk(KERN_INFO
	       "ABAC LSM: Created file /sys/kernel/security/abac/hashmap");

	include_paths_file = securityfs_create_file("include_paths", 0600, abacfs,
						    NULL, &include_paths_fops);
	if (!include_paths_file) {
		printk(KERN_ERR
		       "ABAC LSM: Failed to create file /sys/kernel/security/abac/include_paths");
		destroy_abac_fs();
		return -ENOMEM;
	}
	printk(KERN_INFO
	       "ABAC LSM: Created file /sys/kernel/security/abac/include_paths");

	exclude_paths_file = securityfs_create_file("exclude_paths", 0600, abacfs,
						    NULL, &exclude_paths_fops);
	if (!exclude_paths_file) {
		printk(KERN_ERR
		       "ABAC LSM: Failed to create file /sys/kernel/security/abac/exclude_paths");
		destroy_abac_fs();
		return -ENOMEM;
	}
	printk(KERN_INFO
	       "ABAC LSM: Created file /sys/kernel/security/abac/exclude_paths");

	abac_reset_perf_stats();
	printk(KERN_INFO "ABAC LSM: Securityfs Initialized");
	return 0;
}

fs_initcall(abac_create_fs);
