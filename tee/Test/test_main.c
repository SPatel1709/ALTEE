#include "Enclave_u.h"
#include "attestation.h"
#include "abac_tee_protocol.h"

#include <sgx_urts.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ENCLAVE_FILE "build/enclave/enclave.signed.so"

static void set_attribute(abac_tee_rule_data_t *data, uint32_t index, uint32_t type, const char *name, const char *value)
{
        abac_tee_attribute_t *attribute = &data->attributes[index];

        attribute->type = type;
        strncpy(attribute->name, name, ABAC_TEE_NAME_SIZE - 1);
        strncpy(attribute->value, value, ABAC_TEE_VALUE_SIZE - 1);
}

static bool configure_environment( sgx_enclave_id_t enclave_id, const abac_tee_env_config_t *config)
{
        int enclave_status = ABAC_TEE_INVALID_REQUEST;
        sgx_status_t status;

        status = ecall_set_env_config(enclave_id, &enclave_status,(const uint8_t *)config, sizeof(*config));

        if (status != SGX_SUCCESS ||enclave_status != ABAC_TEE_SUCCESS) {
                fprintf(stderr,"ecall_set_env_config failed: SGX=0x%x enclave=%d\n",status, enclave_status);
                return false;
        }

        return true;
}

static bool load_rule(sgx_enclave_id_t enclave_id,const abac_tee_rule_data_t *rule)
{
        int enclave_status = ABAC_TEE_INVALID_REQUEST;
        sgx_status_t status;

        status = ecall_load_rule(enclave_id, &enclave_status,(const uint8_t *)rule, sizeof(*rule));

        if (status != SGX_SUCCESS || enclave_status != ABAC_TEE_SUCCESS) {
                fprintf(stderr,"ecall_load_rule failed: SGX=0x%x enclave=%d\n",status, enclave_status);
                return false;
        }

        return true;
}

static bool begin_policy_update(sgx_enclave_id_t enclave_id, uint64_t generation)
{
        int enclave_status = ABAC_TEE_INVALID_REQUEST;
        sgx_status_t status;

        status = ecall_begin_policy_update(enclave_id, &enclave_status, generation);

        if (status != SGX_SUCCESS || enclave_status != ABAC_TEE_SUCCESS) {
                fprintf(stderr, "ecall_begin_policy_update failed: SGX=0x%x enclave=%d\n",
                        status, enclave_status);
                return false;
        }

        return true;
}

static bool commit_policy_update(sgx_enclave_id_t enclave_id)
{
        int enclave_status = ABAC_TEE_INVALID_REQUEST;
        sgx_status_t status;

        status = ecall_commit_policy_update(enclave_id, &enclave_status);

        if (status != SGX_SUCCESS || enclave_status != ABAC_TEE_SUCCESS) {
                fprintf(stderr, "ecall_commit_policy_update failed: SGX=0x%x enclave=%d\n",
                        status, enclave_status);
                return false;
        }

        return true;
}

static bool check_policy_generation(sgx_enclave_id_t enclave_id, uint64_t expected)
{
        int enclave_status = ABAC_TEE_INVALID_REQUEST;
        uint64_t generation = 0;
        sgx_status_t status;

        status = ecall_get_policy_generation(enclave_id, &enclave_status, &generation);

        if (status != SGX_SUCCESS || enclave_status != ABAC_TEE_SUCCESS) {
                fprintf(stderr, "ecall_get_policy_generation failed: SGX=0x%x enclave=%d\n",
                        status, enclave_status);
                return false;
        }

        printf("expected generation=%llu active generation=%llu\n",
                (unsigned long long)expected,
                (unsigned long long)generation);

        return generation == expected;
}

static bool evaluate_rule(sgx_enclave_id_t enclave_id,const abac_tee_eval_data_t *evaluation,int expected_match)
{
        int enclave_status = ABAC_TEE_INVALID_REQUEST;
        int matched = 0;
        sgx_status_t status;

        status = ecall_evaluate_rule(enclave_id, &enclave_status,(const uint8_t *)evaluation, sizeof(*evaluation), &matched);

        if (status != SGX_SUCCESS ||enclave_status != ABAC_TEE_SUCCESS)
         {
                fprintf(stderr,
                        "ecall_evaluate_rule failed: "
                        "SGX=0x%x enclave=%d\n",
                        status, enclave_status);
                return false;
        }

        printf("rule=%u day=%u minute=%u expected=%s result=%s\n",evaluation->rule.rule_id,
               evaluation->environment.day_of_week, evaluation->environment.minute_of_day,
               expected_match ? "MATCH" : "NO MATCH", matched ? "MATCH" : "NO MATCH");

        return matched == expected_match;
}

int main(void)
{
        sgx_launch_token_t launch_token = { 0 };
        sgx_misc_attribute_t misc_attributes = { 0 };
        sgx_enclave_id_t enclave_id = 0;
        int launch_token_updated = 0;
        sgx_status_t status;

        abac_tee_env_config_t config = {
                .workday_mask = 62,
                .work_start_minute = 540,
                .work_end_minute = 1020
        };

        abac_tee_rule_data_t rule = { 0 };
        abac_tee_eval_data_t evaluation = { 0 };
        bool success = true;

        status = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &launch_token, &launch_token_updated,
                &enclave_id, &misc_attributes);

        if (status != SGX_SUCCESS) {
                fprintf(stderr, "sgx_create_enclave failed: 0x%x\n",status);
                return 1;
        }

        if (!begin_policy_update(enclave_id, 1)) {
                sgx_destroy_enclave(enclave_id);
                return 1;
        }

        if (!configure_environment(enclave_id, &config)) {
                sgx_destroy_enclave(enclave_id);
                return 1;
        }

        rule.rule_id = 1001;
        rule.attribute_count = 4;

        set_attribute(&rule, 0, ABAC_TEE_USER_ATTRIBUTE,"clearance", "high");
        set_attribute(&rule, 1, ABAC_TEE_OBJECT_ATTRIBUTE,"classification", "secret");
        set_attribute(&rule, 2, ABAC_TEE_ENV_ATTRIBUTE,"day", "weekday");
        set_attribute(&rule, 3, ABAC_TEE_ENV_ATTRIBUTE,"time", "working_hours");

        if (!load_rule(enclave_id, &rule)) {
                sgx_destroy_enclave(enclave_id);
                return 1;
        }

        if (!commit_policy_update(enclave_id) || !check_policy_generation(enclave_id, 1)) {
                sgx_destroy_enclave(enclave_id);
                return 1;
        }

        evaluation.policy_generation = 1;
#ifdef ABAC_TEE_SIMULATION
        if (generate_attestation_quote(enclave_id, 1,
                                       "build/attestation") != 0) {
                fprintf(stderr, "Simulation attestation quote failed\n");
                sgx_destroy_enclave(enclave_id);
                return 1;
        }
#endif

        evaluation.rule = rule;

        /* Tuesday at 10:00: all conditions should match. */
        evaluation.environment.day_of_week = 2;
        evaluation.environment.minute_of_day = 600;
        success = evaluate_rule(enclave_id, &evaluation, 1);

        /* Ordinary protected object attribute mismatch. */
        strncpy(evaluation.rule.attributes[1].value, "public",ABAC_TEE_VALUE_SIZE - 1);
        success = evaluate_rule(enclave_id, &evaluation, 0) && success;

        strncpy(evaluation.rule.attributes[1].value, "secret", ABAC_TEE_VALUE_SIZE - 1);

        /* Saturday at 10:00: weekday condition should fail. */
        evaluation.environment.day_of_week = 6;
        evaluation.environment.minute_of_day = 600;
        success = evaluate_rule(enclave_id, &evaluation, 0) && success;

        /* Tuesday at 20:00: working-hours condition should fail. */
        evaluation.environment.day_of_week = 2;
        evaluation.environment.minute_of_day = 1200;
        success = evaluate_rule(enclave_id, &evaluation, 0) && success;

        sgx_destroy_enclave(enclave_id);

        if (!success) {
                fprintf(stderr, "ABAC TEE self-test failed\n");
                return 1;
        }

        printf("ABAC TEE environmental self-test passed\n");
        return 0;
}
