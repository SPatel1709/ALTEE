#include "Enclave_t.h"
#include "abac_tee_protocol.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <sgx_tseal.h>

#define ABAC_TEE_MAX_RULES 64
#define ABAC_TEE_STATE_MAGIC 0x41424143U
#define ABAC_TEE_STATE_VERSION 1U

typedef struct {
        uint32_t magic;
        uint32_t version;
        abac_tee_rule_data_t rules[ABAC_TEE_MAX_RULES];
        uint8_t rule_used[ABAC_TEE_MAX_RULES];
        abac_tee_env_config_t env_config;
        uint8_t env_configured;
} abac_tee_persistent_state_t;

static abac_tee_persistent_state_t trusted_state = {
        .magic = ABAC_TEE_STATE_MAGIC,
        .version = ABAC_TEE_STATE_VERSION
};

/* Temporary enclave memory used while validating an unsealed state. */
static abac_tee_persistent_state_t recovered_state;

#define trusted_rules          (trusted_state.rules)
#define trusted_rule_used      (trusted_state.rule_used)
#define trusted_env_config     (trusted_state.env_config)
#define trusted_env_configured (trusted_state.env_configured)

static int has_terminator(const char *value, size_t size)
{
        return memchr(value, '\0', size) != NULL;
}

static int valid_rule_data(const abac_tee_rule_data_t *rule)
{
        uint32_t i;

        if (!rule || rule->attribute_count == 0 ||
            rule->attribute_count > ABAC_TEE_MAX_ATTRIBUTES)
                return 0;

        for (i = 0; i < rule->attribute_count; i++) {
                const abac_tee_attribute_t *attribute = &rule->attributes[i];

                if (attribute->type < ABAC_TEE_USER_ATTRIBUTE ||
                    attribute->type > ABAC_TEE_ENV_ATTRIBUTE)
                        return 0;
                if (!has_terminator(attribute->name, ABAC_TEE_NAME_SIZE) ||
                    !has_terminator(attribute->value, ABAC_TEE_VALUE_SIZE))
                        return 0;
        }

        return 1;
}

static int find_rule(uint32_t rule_id)
{
        int i;

        for (i = 0; i < ABAC_TEE_MAX_RULES; i++) {
                if (trusted_rule_used[i] &&
                    trusted_rules[i].rule_id == rule_id)
                        return i;
        }

        return -1;
}

static int same_attribute_identity(
        const abac_tee_attribute_t *expected,
        const abac_tee_attribute_t *actual)
{
        return expected->type == actual->type &&
               strncmp(expected->name, actual->name,
                       ABAC_TEE_NAME_SIZE) == 0;
}

static int current_time_is_working_time(uint32_t minute)
{
        uint32_t start = trusted_env_config.work_start_minute;
        uint32_t end = trusted_env_config.work_end_minute;

        if (start < end)
                return minute >= start && minute < end;

        /* Working window crosses midnight, for example 22:00-06:00. */
        return minute >= start || minute < end;
}

static int attribute_matches(
        const abac_tee_attribute_t *expected,
        const abac_tee_attribute_t *actual,
        const abac_tee_env_context_t *environment)
{
        int condition_result;

        if (!same_attribute_identity(expected, actual))
                return 0;

        if (expected->type == ABAC_TEE_ENV_ATTRIBUTE &&
            strncmp(expected->name, "day",
                    ABAC_TEE_NAME_SIZE) == 0) {
                if (!trusted_env_configured)
                        return 0;

                condition_result =
                        (trusted_env_config.workday_mask &
                         (1U << environment->day_of_week)) != 0;

                if (strncmp(expected->value, "weekday",
                            ABAC_TEE_VALUE_SIZE) == 0)
                        return condition_result;

                if (strncmp(expected->value, "weekend",
                            ABAC_TEE_VALUE_SIZE) == 0)
                        return !condition_result;

                return 0;
        }

        if (expected->type == ABAC_TEE_ENV_ATTRIBUTE &&
            strncmp(expected->name, "time",
                    ABAC_TEE_NAME_SIZE) == 0) {
                if (!trusted_env_configured)
                        return 0;

                condition_result = current_time_is_working_time(
                        environment->minute_of_day);

                if (strncmp(expected->value, "working_hours",
                            ABAC_TEE_VALUE_SIZE) == 0)
                        return condition_result;

                if (strncmp(expected->value, "after_hours",
                            ABAC_TEE_VALUE_SIZE) == 0)
                        return !condition_result;

                return 0;
        }

        return strncmp(expected->value, actual->value,
                       ABAC_TEE_VALUE_SIZE) == 0;
}

int ecall_set_env_config(const uint8_t *config_data,
                         size_t config_size)
{
        const abac_tee_env_config_t *config;

        if (!config_data ||
            config_size != sizeof(abac_tee_env_config_t))
                return ABAC_TEE_INVALID_REQUEST;

        config = (const abac_tee_env_config_t *)config_data;

        if (config->workday_mask == 0 ||
            (config->workday_mask & ~0x7fU) != 0 ||
            config->work_start_minute >= 24U * 60U ||
            config->work_end_minute >= 24U * 60U ||
            config->work_start_minute == config->work_end_minute)
                return ABAC_TEE_INVALID_REQUEST;

        memcpy(&trusted_env_config, config,
               sizeof(trusted_env_config));
        trusted_env_configured = 1;

        return ABAC_TEE_SUCCESS;
}

int ecall_load_rule(const uint8_t *rule_data, size_t rule_size)
{
        const abac_tee_rule_data_t *rule;
        int slot;
        int i;

        if (!rule_data || rule_size != sizeof(abac_tee_rule_data_t))
                return ABAC_TEE_INVALID_REQUEST;

        rule = (const abac_tee_rule_data_t *)rule_data;
        if (!valid_rule_data(rule))
                return ABAC_TEE_INVALID_REQUEST;

        slot = find_rule(rule->rule_id);
        if (slot < 0) {
                for (i = 0; i < ABAC_TEE_MAX_RULES; i++) {
                        if (!trusted_rule_used[i]) {
                                slot = i;
                                break;
                        }
                }
        }

        if (slot < 0)
                return ABAC_TEE_RULE_LIMIT_REACHED;

        memcpy(&trusted_rules[slot], rule, sizeof(*rule));
        trusted_rule_used[slot] = 1;
        return ABAC_TEE_SUCCESS;
}

int ecall_evaluate_rule(const uint8_t *request_data,
                        size_t request_size, int *matched)
{
        const abac_tee_eval_data_t *evaluation;
        const abac_tee_rule_data_t *request;
        const abac_tee_rule_data_t *expected;
        uint32_t i;
        uint32_t j;
        int slot;
        int found;

        if (!matched)
                return ABAC_TEE_INVALID_REQUEST;
        *matched = 0;

        if (!request_data ||
            request_size != sizeof(abac_tee_eval_data_t))
                return ABAC_TEE_INVALID_REQUEST;

        evaluation = (const abac_tee_eval_data_t *)request_data;
        request = &evaluation->rule;

        if (!valid_rule_data(request))
                return ABAC_TEE_INVALID_REQUEST;

        if (evaluation->environment.day_of_week > 6 ||
            evaluation->environment.minute_of_day >= 24U * 60U)
                return ABAC_TEE_INVALID_REQUEST;

        slot = find_rule(request->rule_id);
        if (slot < 0)
                return ABAC_TEE_RULE_NOT_FOUND;

        expected = &trusted_rules[slot];

        for (i = 0; i < expected->attribute_count; i++) {
                found = 0;

                for (j = 0; j < request->attribute_count; j++) {
                        if (attribute_matches(
                                    &expected->attributes[i],
                                    &request->attributes[j],
                                    &evaluation->environment)) {
                                found = 1;
                                break;
                        }
                }

                if (!found)
                        return ABAC_TEE_SUCCESS;
        }

        *matched = 1;
        return ABAC_TEE_SUCCESS;
}

static int valid_persistent_state(
        const abac_tee_persistent_state_t *state)
{
        uint32_t i;

        if (!state ||
            state->magic != ABAC_TEE_STATE_MAGIC ||
            state->version != ABAC_TEE_STATE_VERSION)
                return 0;

        if (!state->env_configured ||
            state->env_config.workday_mask == 0 ||
            (state->env_config.workday_mask & ~0x7fU) != 0 ||
            state->env_config.work_start_minute >= 1440 ||
            state->env_config.work_end_minute >= 1440 ||
            state->env_config.work_start_minute ==
                    state->env_config.work_end_minute)
                return 0;

        for (i = 0; i < ABAC_TEE_MAX_RULES; i++) {
                if (state->rule_used[i] &&
                    !valid_rule_data(&state->rules[i]))
                        return 0;
        }

        return 1;
}

int ecall_get_sealed_state_size(uint32_t *sealed_size)
{
        uint32_t size;

        if (!sealed_size)
                return ABAC_TEE_INVALID_REQUEST;

        size = sgx_calc_sealed_data_size(
                0, (uint32_t)sizeof(trusted_state));
        if (size == UINT32_MAX)
                return ABAC_TEE_SEAL_FAILED;

        *sealed_size = size;
        return ABAC_TEE_SUCCESS;
}

int ecall_seal_state(uint8_t *sealed_data, uint32_t sealed_size)
{
        uint32_t expected_size;
        sgx_status_t status;

        if (!sealed_data || !valid_persistent_state(&trusted_state))
                return ABAC_TEE_STATE_INVALID;

        expected_size = sgx_calc_sealed_data_size(
                0, (uint32_t)sizeof(trusted_state));
        if (expected_size == UINT32_MAX ||
            sealed_size != expected_size)
                return ABAC_TEE_INVALID_REQUEST;

        status = sgx_seal_data(
                0, NULL,
                (uint32_t)sizeof(trusted_state),
                (const uint8_t *)&trusted_state,
                sealed_size,
                (sgx_sealed_data_t *)sealed_data);

        return status == SGX_SUCCESS ?
                ABAC_TEE_SUCCESS : ABAC_TEE_SEAL_FAILED;
}

int ecall_unseal_state(const uint8_t *sealed_data, uint32_t sealed_size)
{
        uint32_t encrypted_size;
        uint32_t plaintext_size;
        uint32_t additional_size = 0;
        sgx_status_t status;

        if (!sealed_data ||
            sealed_size < sizeof(sgx_sealed_data_t))
                return ABAC_TEE_INVALID_REQUEST;

        encrypted_size = sgx_get_encrypt_txt_len(
                (const sgx_sealed_data_t *)sealed_data);
        if (encrypted_size != sizeof(recovered_state))
                return ABAC_TEE_STATE_INVALID;

        plaintext_size = (uint32_t)sizeof(recovered_state);
        memset(&recovered_state, 0, sizeof(recovered_state));

        status = sgx_unseal_data(
                (const sgx_sealed_data_t *)sealed_data,
                NULL, &additional_size,
                (uint8_t *)&recovered_state,
                &plaintext_size);

        if (status != SGX_SUCCESS)
                return ABAC_TEE_UNSEAL_FAILED;

        if (plaintext_size != sizeof(recovered_state) ||
            !valid_persistent_state(&recovered_state))
                return ABAC_TEE_STATE_INVALID;

        memcpy(&trusted_state, &recovered_state,
               sizeof(trusted_state));
        memset(&recovered_state, 0, sizeof(recovered_state));

        return ABAC_TEE_SUCCESS;
}

int ecall_clear_rules(void)
{
        memset(trusted_rules, 0, sizeof(trusted_rules));
        memset(trusted_rule_used, 0, sizeof(trusted_rule_used));
        return ABAC_TEE_SUCCESS;
}
