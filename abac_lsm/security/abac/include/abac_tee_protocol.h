#ifndef ABAC_TEE_PROTOCOL_H
#define ABAC_TEE_PROTOCOL_H



// The types defined in Kernel and SGX are different
#ifdef __KERNEL__
#include <linux/types.h>
typedef __u32 abac_tee_u32;
typedef __u64 abac_tee_u64;
typedef __s32 abac_tee_s32;
#else
#include <stdint.h>
typedef uint32_t abac_tee_u32;
typedef uint64_t abac_tee_u64;
typedef int32_t abac_tee_s32;
#endif

#define ABAC_TEE_MAX_ATTRIBUTES 16
#define ABAC_TEE_NAME_SIZE      64
#define ABAC_TEE_VALUE_SIZE     128

enum abac_tee_attribute_type {
        ABAC_TEE_USER_ATTRIBUTE = 1,
        ABAC_TEE_OBJECT_ATTRIBUTE = 2,
        ABAC_TEE_ENV_ATTRIBUTE = 3
};

enum abac_tee_status {
        ABAC_TEE_SUCCESS = 0,
        ABAC_TEE_INVALID_REQUEST = -1,
        ABAC_TEE_RULE_NOT_FOUND = -2,
        ABAC_TEE_RULE_LIMIT_REACHED = -3,
        ABAC_TEE_SERVICE_UNAVAILABLE = -4,
        ABAC_TEE_SEAL_FAILED = -5,
        ABAC_TEE_UNSEAL_FAILED = -6,

        // Adding new policy requires to have these states
        // It is divied into add->stage->commit/abort type of logic.
        ABAC_TEE_STATE_INVALID = -7,
        ABAC_TEE_UPDATE_IN_PROGRESS = -8,
        ABAC_TEE_NO_UPDATE = -9,
        ABAC_TEE_GENERATION_INVALID = -10
};

typedef struct {
        abac_tee_u32 type;
        char name[ABAC_TEE_NAME_SIZE];
        char value[ABAC_TEE_VALUE_SIZE];
} abac_tee_attribute_t;

typedef struct {
        abac_tee_u32 rule_id;
        abac_tee_u32 attribute_count;
        abac_tee_attribute_t attributes[ABAC_TEE_MAX_ATTRIBUTES];
} abac_tee_rule_data_t;

/*
 * Protected environmental configuration stored inside the enclave.
 * workday_mask uses the tm_wday convention:
 * bit 0 = Sunday, bit 1 = Monday, ..., bit 6 = Saturday.
 * Time values are minutes after midnight.
 */
typedef struct {
        abac_tee_u32 workday_mask;
        abac_tee_u32 work_start_minute;
        abac_tee_u32 work_end_minute;
} abac_tee_env_config_t;

/* Raw runtime context supplied for one access decision. */
typedef struct {
        abac_tee_u32 day_of_week;
        abac_tee_u32 minute_of_day;
} abac_tee_env_context_t;

/*
 * Complete input to enclave evaluation:
 * candidate rule values collected by the kernel plus raw runtime context.
 */
typedef struct {
        abac_tee_u64 policy_generation;
        abac_tee_rule_data_t rule;
        abac_tee_env_context_t environment;
} abac_tee_eval_data_t;

typedef struct {
        abac_tee_u64 request_id;
        abac_tee_u64 policy_generation;
        abac_tee_rule_data_t rule;
} abac_tee_ipc_request_t;

typedef struct {
        abac_tee_u64 request_id;
        abac_tee_u64 policy_generation;
        abac_tee_s32 status;
        abac_tee_s32 matched;
} abac_tee_ipc_response_t;

#endif
