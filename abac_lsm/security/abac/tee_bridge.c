// SPDX-License-Identifier: GPL-2.0-only

#include <linux/completion.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/wait.h>

#include "include/tee_bridge.h"

#define ABAC_TEE_TIMEOUT_MS 2000

/*
 * eval_lock permits only one outstanding TEE evaluation. This is IPC
 * synchronization; policy-update synchronization remains deferred.
 */
static DEFINE_MUTEX(abac_tee_eval_lock);
static DEFINE_MUTEX(abac_tee_state_lock);
static DECLARE_WAIT_QUEUE_HEAD(abac_tee_request_wait);
static DECLARE_COMPLETION(abac_tee_response_ready);

static abac_tee_ipc_request_t current_request;
static abac_tee_ipc_response_t current_response;
static abac_tee_u64 request_sequence;
static bool request_pending;
static bool response_expected;
static abac_tee_u64 active_generation;
static abac_tee_u64 pending_generation;
static bool policy_update_in_progress;

static ssize_t abac_tee_request_read(struct file *file, char __user *buffer, size_t len, loff_t *offset)
{
        abac_tee_ipc_request_t *request;
        ssize_t ret;

        (void)file;
        (void)offset;

        request = kmalloc(sizeof(*request), GFP_KERNEL);
        if (!request)
                return -ENOMEM;

        if (len < sizeof(*request)) {
                ret = -EINVAL;
                goto out_free;
        }

retry:
        ret = wait_event_interruptible(abac_tee_request_wait,READ_ONCE(request_pending));
        if (ret)
                goto out_free;

        mutex_lock(&abac_tee_state_lock);
        if (!request_pending) {
                mutex_unlock(&abac_tee_state_lock);
                goto retry;
        }

        *request = current_request;
        request_pending = false;
        mutex_unlock(&abac_tee_state_lock);

        if (copy_to_user(buffer, request, sizeof(*request))) {
                ret = -EFAULT;
                goto out_free;
        }

        ret = sizeof(*request);

out_free:
        kfree(request);
        return ret;
}

static ssize_t abac_tee_response_write(struct file *file,const char __user *buffer,size_t len, loff_t *offset)
{
	abac_tee_ipc_response_t response;
	bool accepted = false;

	(void)file;
	(void)offset;

	if (len < sizeof(response))
		return -EINVAL;
	if (copy_from_user(&response, buffer, sizeof(response)))
		return -EFAULT;

	mutex_lock(&abac_tee_state_lock);
	if (response_expected && response.request_id == current_request.request_id && response.policy_generation == current_request.policy_generation) {
		current_response = response;
		response_expected = false;
		accepted = true;
	}
	mutex_unlock(&abac_tee_state_lock);

	if (!accepted)
		return -ESTALE;

	complete(&abac_tee_response_ready);
	return sizeof(response);
}

static ssize_t abac_tee_policy_read(struct file *file, char __user *buffer, size_t len, loff_t *offset)
{
        char state[128];
        abac_tee_u64 active;
        abac_tee_u64 pending;
        bool updating;
        int size;

        (void)file;

        mutex_lock(&abac_tee_state_lock);
        active = active_generation;
        pending = pending_generation;
        updating = policy_update_in_progress;
        mutex_unlock(&abac_tee_state_lock);

        size = scnprintf(state, sizeof(state), "generation=%llu\npending=%llu\nupdating=%u\n", active, pending, updating);

        return simple_read_from_buffer(buffer, len, offset, state, size);
}

static ssize_t abac_tee_policy_write(struct file *file,const char __user *buffer,size_t len, loff_t *offset)
{
        char command[64];
        char *generation_text;
        abac_tee_u64 generation;
        int ret = 0;

        (void)file;
        (void)offset;

        if (!len || len >= sizeof(command))
                return -EINVAL;
        if (copy_from_user(command, buffer, len))
                return -EFAULT;

        command[len] = '\0';
        strim(command);

        generation_text = strchr(command, ' ');
        if (!generation_text)
                return -EINVAL;

        *generation_text++ = '\0';
        generation_text = strim(generation_text);
        if (kstrtoull(generation_text, 10, &generation) || !generation)
                return -EINVAL;

        mutex_lock(&abac_tee_eval_lock);
        mutex_lock(&abac_tee_state_lock);

        if (!strcmp(command, "sync")) {
                if (!policy_update_in_progress && (!active_generation || active_generation == generation))
                        active_generation = generation;
                else
                        ret = -ESTALE;

        } else if (!strcmp(command, "begin")) {
                if (!active_generation)
                        ret = -EAGAIN;
                else if (policy_update_in_progress)
                        ret = -EBUSY;
                else if (generation <= active_generation)
                        ret = -EINVAL;
                else {
                        pending_generation = generation;
                        policy_update_in_progress = true;
                }
        } else if (!strcmp(command, "commit")) {
                if (!policy_update_in_progress ||
                    pending_generation != generation)
                        ret = -ESTALE;
                else {
                        active_generation = generation;
                        pending_generation = 0;
                        policy_update_in_progress = false;
                }
        } else if (!strcmp(command, "abort")) {
                if (!policy_update_in_progress ||
                    pending_generation != generation)
                        ret = -ESTALE;
                else {
                        pending_generation = 0;
                        policy_update_in_progress = false;
                }
        } else {
                ret = -EINVAL;
        }

        mutex_unlock(&abac_tee_state_lock);
        mutex_unlock(&abac_tee_eval_lock);

        return ret ? ret : len;
}

const struct file_operations abac_tee_policy_fops = {
        .owner = THIS_MODULE,
        .read = abac_tee_policy_read,
        .write = abac_tee_policy_write,
};

const struct file_operations abac_tee_request_fops = {
	.owner = THIS_MODULE,
	.read = abac_tee_request_read,
};

const struct file_operations abac_tee_response_fops = {
	.owner = THIS_MODULE,
	.write = abac_tee_response_write,
};

int abac_tee_evaluate_rule(const abac_tee_rule_data_t *rule)
{
        abac_tee_u64 request_id;
        abac_tee_u64 generation;
        long wait_result;
        int matched = 0;

        if (!rule || rule->attribute_count == 0 || rule->attribute_count > ABAC_TEE_MAX_ATTRIBUTES)
                return 0;

        mutex_lock(&abac_tee_eval_lock);

        mutex_lock(&abac_tee_state_lock);
        if (policy_update_in_progress || !active_generation) {
                mutex_unlock(&abac_tee_state_lock);
                mutex_unlock(&abac_tee_eval_lock);
                return 0;
        }

        generation = active_generation;
        mutex_unlock(&abac_tee_state_lock);

        reinit_completion(&abac_tee_response_ready);

        mutex_lock(&abac_tee_state_lock);
        memset(&current_request, 0, sizeof(current_request));
        memset(&current_response, 0, sizeof(current_response));

        request_id = ++request_sequence;
        if (!request_id)
                request_id = ++request_sequence;

        current_request.request_id = request_id;
        current_request.policy_generation = generation;
        current_request.rule = *rule;
        request_pending = true;
        response_expected = true;
        mutex_unlock(&abac_tee_state_lock);

        wake_up_interruptible(&abac_tee_request_wait);

        wait_result = wait_for_completion_interruptible_timeout(&abac_tee_response_ready,
                                                                 msecs_to_jiffies(ABAC_TEE_TIMEOUT_MS));

        mutex_lock(&abac_tee_state_lock);
        if (wait_result > 0 && current_response.request_id == request_id &&
            current_response.policy_generation == generation &&
            current_response.status == ABAC_TEE_SUCCESS && current_response.matched)
                matched = 1;

        if (current_request.request_id == request_id) {
                request_pending = false;
                response_expected = false;
        }
        mutex_unlock(&abac_tee_state_lock);

        if (wait_result <= 0)
                pr_warn_ratelimited("ABAC TEE: service unavailable or timed out\n");

        mutex_unlock(&abac_tee_eval_lock);
        return matched;
}
