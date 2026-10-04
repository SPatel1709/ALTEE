/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ABAC_TEE_BRIDGE_H
#define _ABAC_TEE_BRIDGE_H

#include <linux/fs.h>

#include "abac_tee_protocol.h"

extern const struct file_operations abac_tee_request_fops;
extern const struct file_operations abac_tee_response_fops;
extern const struct file_operations abac_tee_policy_fops;
extern const struct file_operations abac_tee_policy_fops;

/*
 * Returns 1 when the enclave matches the complete sensitive part
 * of the rule. Any error, timeout or mismatch returns 0 (fail closed).
 */
int abac_tee_evaluate_rule(const abac_tee_rule_data_t *rule);

#endif
