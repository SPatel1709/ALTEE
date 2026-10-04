#define _POSIX_C_SOURCE 200809L
#include "Enclave_u.h"
#include "abac_tee_protocol.h"

#include <sgx_urts.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define ENCLAVE_FILE "build/enclave/enclave.signed.so"
#define TEE_REQUEST_FILE "/sys/kernel/security/abac/tee_request"
#define TEE_RESPONSE_FILE "/sys/kernel/security/abac/tee_response"
#define TEE_POLICY_FILE "/sys/kernel/security/abac/tee_policy"
#define TEE_RULES_FILE "/etc/abac/tee_rules.conf"
#define TEE_STATE_DIRECTORY "/var/lib/abac-tee"
#define TEE_SEALED_STATE_FILE "/var/lib/abac-tee/state.sealed"
#define TEE_SEALED_TEMP_FILE "/var/lib/abac-tee/state.sealed.tmp"
#define TEE_ENV_FILE "/etc/abac/tee_env.conf"
#define TEE_UPDATE_MARKER "/var/lib/abac-tee/update.pending"

static void set_attribute(abac_tee_rule_data_t *rule, uint32_t index, uint32_t type, const char *name, const char *value)
{
        abac_tee_attribute_t *attribute = &rule->attributes[index];

        attribute->type = type;
        strncpy(attribute->name, name, ABAC_TEE_NAME_SIZE - 1);
        strncpy(attribute->value, value, ABAC_TEE_VALUE_SIZE - 1);
}

static int attribute_type(const char *text)
{
        if (strcmp(text, "user") == 0)
                return ABAC_TEE_USER_ATTRIBUTE;
        if (strcmp(text, "object") == 0)
                return ABAC_TEE_OBJECT_ATTRIBUTE;
        if (strcmp(text, "env") == 0)
                return ABAC_TEE_ENV_ATTRIBUTE;
        return 0;
}

static int load_environment_config(sgx_enclave_id_t enclave_id, const char *path)
{
        abac_tee_env_config_t config = { 0 };
        unsigned int value;
        int have_mask = 0;
        int have_start = 0;
        int have_end = 0;
        int enclave_status = ABAC_TEE_INVALID_REQUEST;
        sgx_status_t status;
        char line[128];
        FILE *file;

        file = fopen(path, "r");
        if (!file) {
                perror("open TEE environment file");
                return -1;
        }

        while (fgets(line, sizeof(line), file)) {
                if (sscanf(line, "workday_mask=%u", &value) == 1)
                {
                        config.workday_mask = value;
                        have_mask = 1;
                }
                else if (sscanf(line, "work_start_minute=%u", &value) == 1)
                {
                        config.work_start_minute = value;
                        have_start = 1;
                }
                else if (sscanf(line, "work_end_minute=%u", &value) == 1)
                {
                        config.work_end_minute = value;
                        have_end = 1;
                }
        }

        fclose(file);

        if (!have_mask || !have_start || !have_end) {
                fprintf(stderr, "Incomplete TEE environment configuration\n");
                return -1;
        }

        status = ecall_set_env_config(enclave_id, &enclave_status,(const uint8_t *)&config, sizeof(config));

        if (status != SGX_SUCCESS ||enclave_status != ABAC_TEE_SUCCESS)
         {
                fprintf(stderr,"Failed to configure TEE environment: SGX=0x%x enclave=%d\n",status, enclave_status);
                return -1;
        }

        printf("TEE environment configured: mask=%u window=%u-%u\n",
                        config.workday_mask,config.work_start_minute,config.work_end_minute);

        return 0;
}

static int get_current_environment(abac_tee_env_context_t *environment)
{
        struct tm local_time;
        time_t now;

        if (!environment)
                return -1;

        now = time(NULL);
        if (now == (time_t)-1 || localtime_r(&now, &local_time) == NULL)
                return -1;

        environment->day_of_week = (uint32_t)local_time.tm_wday;
        environment->minute_of_day = (uint32_t)(local_time.tm_hour * 60 + local_time.tm_min);

        return 0;
}

static int load_rule(sgx_enclave_id_t enclave_id, const abac_tee_rule_data_t *rule)
{
        int enclave_status = ABAC_TEE_INVALID_REQUEST;
        sgx_status_t status;

        status = ecall_load_rule(enclave_id, &enclave_status, (const uint8_t *)rule, sizeof(*rule));
        if (status != SGX_SUCCESS ||enclave_status != ABAC_TEE_SUCCESS)
        {
                fprintf(stderr,"Failed to load rule %u: SGX=0x%x enclave=%d\n",rule->rule_id, status, enclave_status);
                return -1;
        }

        return 0;
}

static int load_rules_from_file(sgx_enclave_id_t enclave_id, const char *path)
{
        char line[4096];
        unsigned int line_number = 0;
        int loaded = 0;
        FILE *file;

        file = fopen(path, "r");
        if (!file) {
                perror("open TEE rules file");
                return -1;
        }

        while (fgets(line, sizeof(line), file)) {
                abac_tee_rule_data_t rule = { 0 };
                char *attributes;
                char *saveptr = NULL;
                char *token;
                char *endptr;
                unsigned long rule_id;

                line_number++;
                attributes = strchr(line, '|');
                if (!attributes) {
                        fprintf(stderr, "Invalid TEE rule at line %u\n", line_number);
                        fclose(file);
                        return -1;
                }

                *attributes++ = '\0';
                errno = 0;
                rule_id = strtoul(line, &endptr, 10);
                if (errno || *endptr != '\0' || rule_id == 0 || rule_id > UINT32_MAX) {
                        fprintf(stderr, "Invalid rule ID at line %u\n", line_number);
                        fclose(file);
                        return -1;
                }
                rule.rule_id = (uint32_t)rule_id;

                token = strtok_r(attributes, ",\r\n", &saveptr);
                while (token) {
                        char *type_text;
                        char *name;
                        char *value;
                        char *colon;
                        char *equals;
                        int type;

                        if (rule.attribute_count >=ABAC_TEE_MAX_ATTRIBUTES)
                         {
                                fprintf(stderr,"Too many TEE attributes in rule %u\n",rule.rule_id);
                                fclose(file);
                                return -1;
                        }

                        type_text = token;
                        colon = strchr(token, ':');
                        equals = colon ? strchr(colon + 1, '=') : NULL;

                        if (!colon || !equals) {
                                fprintf(stderr,"Invalid attribute at line %u\n",line_number);
                                fclose(file);
                                return -1;
                        }

                        *colon = '\0';
                        *equals = '\0';
                        name = colon + 1;
                        value = equals + 1;
                        type = attribute_type(type_text);

                        if (!type || !*name || !*value ||strlen(name) >= ABAC_TEE_NAME_SIZE ||strlen(value) >= ABAC_TEE_VALUE_SIZE) {
                                fprintf(stderr,"Invalid attribute at line %u\n",line_number);
                                fclose(file);
                                return -1;
                        }

                        set_attribute(&rule, rule.attribute_count,(uint32_t)type, name, value);
                        rule.attribute_count++;
                        token = strtok_r(NULL, ",\r\n", &saveptr);
                }

                if (rule.attribute_count == 0 ||load_rule(enclave_id, &rule) != 0)
                 {
                        fclose(file);
                        return -1;
                }

                loaded++;
        }

        if (ferror(file)) {
                perror("read TEE rules file");
                fclose(file);
                return -1;
        }

        fclose(file);
        return loaded;
}

static int read_complete(int fd, uint8_t *buffer, size_t size)
{
        size_t total = 0;

        while (total < size) {
                ssize_t bytes = read(fd, buffer + total, size - total);

                if (bytes < 0) {
                        if (errno == EINTR)
                                continue;
                        return -1;
                }
                if (bytes == 0)
                        return -1;

                total += (size_t)bytes;
        }

        return 0;
}

static int write_complete(int fd, const uint8_t *buffer, size_t size)
{
        size_t total = 0;

        while (total < size) {
                ssize_t bytes = write(fd, buffer + total, size - total);

                if (bytes < 0) {
                        if (errno == EINTR)
                                continue;
                        return -1;
                }
                if (bytes == 0)
                        return -1;

                total += (size_t)bytes;
        }

        return 0;
}

static int save_sealed_state(sgx_enclave_id_t enclave_id)
{
        int enclave_status = ABAC_TEE_INVALID_REQUEST;
        uint32_t sealed_size = 0;
        uint8_t *sealed_data = NULL;
        sgx_status_t status;
        int fd = -1;
        int result = -1;

        status = ecall_get_sealed_state_size(enclave_id, &enclave_status, &sealed_size);
        if (status != SGX_SUCCESS || enclave_status != ABAC_TEE_SUCCESS || sealed_size == 0) {
                fprintf(stderr, "Get sealed-state size failed: SGX=0x%x enclave=%d\n",status, enclave_status);
                return -1;
        }

        sealed_data = malloc(sealed_size);
        if (!sealed_data)
                return -1;

        status = ecall_seal_state(enclave_id, &enclave_status,sealed_data, sealed_size);
        if (status != SGX_SUCCESS ||enclave_status != ABAC_TEE_SUCCESS)
         {
                fprintf(stderr,"Seal state failed: SGX=0x%x enclave=%d\n",status, enclave_status);
                goto out;
        }

        if (mkdir(TEE_STATE_DIRECTORY, 0700) != 0 &&
            errno != EEXIST) {
                perror("create TEE state directory");
                goto out;
        }

        fd = open(TEE_SEALED_TEMP_FILE,O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0) {
                perror("open temporary sealed state");
                goto out;
        }

        if (write_complete(fd, sealed_data, sealed_size) != 0) {
                perror("write sealed state");
                goto out;
        }

        if (fsync(fd) != 0) {
                perror("fsync sealed state");
                goto out;
        }

        if (close(fd) != 0) {
                fd = -1;
                perror("close sealed state");
                goto out;
        }
        fd = -1;

        if (rename(TEE_SEALED_TEMP_FILE,TEE_SEALED_STATE_FILE) != 0)
         {
                perror("install sealed state");
                goto out;
        }

        printf("TEE state sealed to %s (%u bytes)\n",TEE_SEALED_STATE_FILE, sealed_size);
        result = 0;

out:
        if (fd >= 0)
                close(fd);
        if (result != 0)
                unlink(TEE_SEALED_TEMP_FILE);
        if (sealed_data) {
                memset(sealed_data, 0, sealed_size);
                free(sealed_data);
        }

        return result;
}

/*
 * Returns 1 when restored, 0 when no state exists yet,
 * and -1 when an existing state cannot be trusted.
 */
static int load_sealed_state(sgx_enclave_id_t enclave_id)
{
        int enclave_status = ABAC_TEE_INVALID_REQUEST;
        uint32_t expected_size = 0;
        uint8_t *sealed_data = NULL;
        struct stat state_stat;
        sgx_status_t status;
        int fd;
        int result = -1;

        fd = open(TEE_SEALED_STATE_FILE, O_RDONLY);
        if (fd < 0) {
                if (errno == ENOENT)
                        return 0;
                perror("open sealed state");
                return -1;
        }

        status = ecall_get_sealed_state_size(enclave_id, &enclave_status, &expected_size);

        if (status != SGX_SUCCESS || enclave_status != ABAC_TEE_SUCCESS || expected_size == 0) {
                fprintf(stderr,"Get sealed-state size failed: SGX=0x%x enclave=%d\n",status, enclave_status);
                goto out;
        }

        if (fstat(fd, &state_stat) != 0) {
                perror("stat sealed state");
                goto out;
        }

        if (state_stat.st_size != (off_t)expected_size) {
                fprintf(stderr,"Invalid sealed-state size: expected=%u actual=%lld\n",
                                        expected_size, (long long)state_stat.st_size);
                goto out;
        }

        sealed_data = malloc(expected_size);
        if (!sealed_data)
                goto out;

        if (read_complete(fd, sealed_data, expected_size) != 0) {
                fprintf(stderr, "Could not read complete sealed state\n");
                goto out;
        }

        status = ecall_unseal_state(enclave_id, &enclave_status,sealed_data, expected_size);

        if (status != SGX_SUCCESS ||enclave_status != ABAC_TEE_SUCCESS)
        {
                fprintf(stderr,"Unseal state failed: SGX=0x%x enclave=%d\n",status, enclave_status);
                goto out;
        }

        printf("TEE state restored from %s\n",TEE_SEALED_STATE_FILE);
        result = 1;

out:
        close(fd);
        if (sealed_data) {
                memset(sealed_data, 0, expected_size);
                free(sealed_data);
        }
        return result;
}


static int get_policy_generation(sgx_enclave_id_t enclave_id, uint64_t *generation)
{
        int enclave_status = ABAC_TEE_INVALID_REQUEST;
        sgx_status_t status;

        status = ecall_get_policy_generation(enclave_id, &enclave_status, generation);

        if (status != SGX_SUCCESS || enclave_status != ABAC_TEE_SUCCESS) {
                fprintf(stderr, "Get policy generation failed: SGX=0x%x enclave=%d\n", status, enclave_status);
                return -1;
        }

        return 0;
}

static int begin_policy_update(sgx_enclave_id_t enclave_id, uint64_t generation)
{
        int enclave_status = ABAC_TEE_INVALID_REQUEST;
        sgx_status_t status;

        status = ecall_begin_policy_update(enclave_id, &enclave_status, generation);

        if (status != SGX_SUCCESS || enclave_status != ABAC_TEE_SUCCESS) {
                fprintf(stderr, "Begin policy update failed: generation=%llu SGX=0x%x enclave=%d\n",
                        (unsigned long long)generation, status, enclave_status);
                return -1;
        }

        return 0;
}

static void abort_policy_update(sgx_enclave_id_t enclave_id)
{
        int enclave_status = ABAC_TEE_INVALID_REQUEST;
        sgx_status_t status;

        status = ecall_abort_policy_update(enclave_id, &enclave_status);

        if (status != SGX_SUCCESS || enclave_status != ABAC_TEE_SUCCESS)
                fprintf(stderr, "Abort policy update failed: SGX=0x%x enclave=%d\n", status, enclave_status);
}

static int commit_policy_update(sgx_enclave_id_t enclave_id)
{
        int enclave_status = ABAC_TEE_INVALID_REQUEST;
        sgx_status_t status;

        status = ecall_commit_policy_update(enclave_id, &enclave_status);

        if (status != SGX_SUCCESS || enclave_status != ABAC_TEE_SUCCESS) {
                fprintf(stderr, "Commit policy update failed: SGX=0x%x enclave=%d\n", status, enclave_status);
                return -1;
        }

        return 0;
}

static int load_policy_transaction(sgx_enclave_id_t enclave_id, uint64_t generation, int *loaded_rules)
{
        int loaded;

        if (!loaded_rules)
                return -1;

        if (begin_policy_update(enclave_id, generation) != 0)
                return -1;

        if (load_environment_config(enclave_id, TEE_ENV_FILE) != 0)
                goto abort_update;

        loaded = load_rules_from_file(enclave_id, TEE_RULES_FILE);
        if (loaded < 0)
                goto abort_update;

        if (commit_policy_update(enclave_id) != 0)
                goto abort_update;

        if (save_sealed_state(enclave_id) != 0)
                return -1;

        *loaded_rules = loaded;
        printf("TEE policy generation %llu committed: %d rule(s)\n",
                (unsigned long long)generation, loaded);

        return 0;

abort_update:
        abort_policy_update(enclave_id);
        return -1;
}

static int kernel_policy_command(const char *command, uint64_t generation)
{
        char buffer[64];
        ssize_t bytes;
        int size;
        int fd;

        size = snprintf(buffer, sizeof(buffer), "%s %llu\n", command,
                        (unsigned long long)generation);
        if (size < 0 || (size_t)size >= sizeof(buffer))
                return -1;

        fd = open(TEE_POLICY_FILE, O_WRONLY);
        if (fd < 0) {
                perror("open tee_policy");
                return -1;
        }

        bytes = write(fd, buffer, size);
        close(fd);

        if (bytes != size) {
                if (bytes < 0)
                        perror("write tee_policy");
                else
                        fprintf(stderr, "Incomplete tee_policy command\n");
                return -1;
        }

        return 0;
}

static int read_update_generation(uint64_t *generation)
{
        unsigned long long value;
        FILE *file;

        file = fopen(TEE_UPDATE_MARKER, "r");
        if (!file) {
                perror("open update marker");
                return -1;
        }

        if (fscanf(file, "%llu", &value) != 1 || !value) {
                fprintf(stderr, "Invalid policy generation in update marker\n");
                fclose(file);
                return -1;
        }

        fclose(file);
        *generation = (uint64_t)value;
        return 0;
}

int main(void)
{
        sgx_launch_token_t launch_token = { 0 };
        sgx_misc_attribute_t misc_attributes = { 0 };
        sgx_enclave_id_t enclave_id = 0;
        int launch_token_updated = 0;
        int request_fd;
        int response_fd;
        int loaded_rules = 0;
        int restored_state;
        int update_pending;
        uint64_t active_generation = 0;
        uint64_t requested_generation = 0;
        sgx_status_t status;

        status = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &launch_token, &launch_token_updated,
                                    &enclave_id, &misc_attributes);

                                    if (status != SGX_SUCCESS)
        {
                fprintf(stderr, "sgx_create_enclave failed: 0x%x\n", status);
                return 1;
        }

        update_pending = (access(TEE_UPDATE_MARKER, F_OK) == 0);
        if (update_pending && read_update_generation(&requested_generation) != 0) {
                sgx_destroy_enclave(enclave_id);
                return 1;
        }

        restored_state = load_sealed_state(enclave_id);
        if (restored_state < 0) {
                /*
                 * A blob exists but cannot be authenticated or validated.
                 * Do not silently trust the plaintext configuration.
                 */
                sgx_destroy_enclave(enclave_id);
                return 1;
        }

        if (restored_state == 0) {
                active_generation = 1;

                if (load_policy_transaction(enclave_id, active_generation, &loaded_rules) != 0) {
                        sgx_destroy_enclave(enclave_id);
                        return 1;
                }
        }
        else {
                if (get_policy_generation(enclave_id, &active_generation) != 0) {
                        sgx_destroy_enclave(enclave_id);
                        return 1;
                }

                if (update_pending) {
                        if (active_generation == UINT64_MAX ||
                            requested_generation != active_generation + 1) {
                                fprintf(stderr, "Invalid requested policy generation\n");
                                sgx_destroy_enclave(enclave_id);
                                return 1;
                        }

                        if (load_policy_transaction(enclave_id, requested_generation, &loaded_rules) != 0) {
                                sgx_destroy_enclave(enclave_id);
                                return 1;
                        }

                        active_generation = requested_generation;
                }
        }

        if (update_pending && unlink(TEE_UPDATE_MARKER) != 0) {
                perror("remove policy update marker");
                sgx_destroy_enclave(enclave_id);
                return 1;
        }

        if (!update_pending &&
            kernel_policy_command("sync", active_generation) != 0) {
                sgx_destroy_enclave(enclave_id);
                return 1;
        }

        request_fd = open(TEE_REQUEST_FILE, O_RDONLY);
        if (request_fd < 0) {
                perror("open tee_request");
                sgx_destroy_enclave(enclave_id);
                return 1;
        }

        response_fd = open(TEE_RESPONSE_FILE, O_WRONLY);
        if (response_fd < 0) {
                perror("open tee_response");
                close(request_fd);
                sgx_destroy_enclave(enclave_id);
                return 1;
        }

        if (update_pending)
                printf("ABAC TEE daemon ready; policy generation %llu updated and sealed\n",
                        (unsigned long long)active_generation);
        else if (restored_state == 1)
                printf("ABAC TEE daemon ready; sealed generation %llu restored\n",
                        (unsigned long long)active_generation);
        else
                printf("ABAC TEE daemon ready; generation %llu initialized with %d rule(s)\n",
                        (unsigned long long)active_generation, loaded_rules);
        fflush(stdout);

        while(1) {
                abac_tee_ipc_request_t request;
                abac_tee_ipc_response_t response = { 0 };
                abac_tee_eval_data_t evaluation = { 0 };
                int enclave_status = ABAC_TEE_INVALID_REQUEST;
                int matched = 0;
                ssize_t bytes;

                bytes = read(request_fd, &request, sizeof(request));
                if (bytes < 0) {
                        if (errno == EINTR)
                                continue;
                        perror("read tee_request");
                        break;
                }
                if ((size_t)bytes != sizeof(request)) {
                        fprintf(stderr, "Invalid TEE request size: %zd\n",
                                bytes);
                        continue;
                }

                response.request_id = request.request_id;
                response.policy_generation = request.policy_generation;
                evaluation.policy_generation = request.policy_generation;
                evaluation.rule = request.rule;

                if (get_current_environment(&evaluation.environment) != 0)
                {
                        response.status = ABAC_TEE_SERVICE_UNAVAILABLE;
                        response.matched = 0;
                }
                else
                {

                        status = ecall_evaluate_rule(enclave_id, &enclave_status,(const uint8_t *)&evaluation,
                                                                sizeof(evaluation), &matched);

                        if (status != SGX_SUCCESS)
                        {
                                response.status = ABAC_TEE_SERVICE_UNAVAILABLE;
                                response.matched = 0;
                        }
                        else
                        {
                                response.status = enclave_status;
                                response.matched = matched;
                        }
                }

                bytes = write(response_fd, &response, sizeof(response));
                if ((size_t)bytes != sizeof(response)) {
                        if (bytes < 0)
                                perror("write tee_response");
                        else
                                fprintf(stderr,"Invalid TEE response write: %zd\n",bytes);
                        break;
                }

                printf("request=%llu rule=%u attributes=%u result=%s\n",(unsigned long long)request.request_id,
                        request.rule.rule_id, request.rule.attribute_count,response.matched ? "MATCH" : "NO MATCH");
                fflush(stdout);
        }

        close(response_fd);
        close(request_fd);
        sgx_destroy_enclave(enclave_id);
        return 1;
}
