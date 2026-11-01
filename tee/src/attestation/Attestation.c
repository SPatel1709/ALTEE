#define _POSIX_C_SOURCE 200809L

#include "attestation.h"
#include "Enclave_u.h"
#include "abac_tee_protocol.h"

#include <sgx_quote.h>
#include <sgx_uae_epid.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define QUOTE_FILE "attestation.quote"
#define QUOTE_TEMP_FILE "attestation.quote.tmp"
#define METADATA_FILE "attestation.meta"
#define METADATA_TEMP_FILE "attestation.meta.tmp"

#ifdef ABAC_TEE_SIMULATION
#define ATTESTATION_HARDWARE 0
#else
#define ATTESTATION_HARDWARE 1
#endif

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

                total += (size_t)bytes;
        }

        return 0;
}

static int random_nonce(uint8_t nonce[ABAC_TEE_ATTESTATION_NONCE_SIZE])
{
        int fd;
        int result;

        fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0) {
                perror("open /dev/urandom");
                return -1;
        }

        result = read_complete(fd, nonce, ABAC_TEE_ATTESTATION_NONCE_SIZE);
        close(fd);

        if (result != 0)
                perror("read /dev/urandom");

        return result;
}

static int make_path(char *path, size_t size, const char *directory,
                     const char *name)
{
        int written = snprintf(path, size, "%s/%s", directory, name);

        if (written < 0 || (size_t)written >= size)
                return -1;

        return 0;
}

static int write_atomic_file(const char *path, const char *temporary_path,
                             const uint8_t *data, size_t size)
{
        int fd;

        fd = open(temporary_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0)
                return -1;

        if (write_complete(fd, data, size) != 0 || fsync(fd) != 0) {
                close(fd);
                unlink(temporary_path);
                return -1;
        }

        if (close(fd) != 0) {
                unlink(temporary_path);
                return -1;
        }

        if (rename(temporary_path, path) != 0) {
                unlink(temporary_path);
                return -1;
        }

        return 0;
}

int generate_attestation_quote(sgx_enclave_id_t enclave_id,
                               uint64_t policy_generation,
                               const char *output_directory)
{
        sgx_target_info_t target_info = { 0 };
        sgx_epid_group_id_t group_id = { 0 };
        sgx_spid_t spid = { 0 };
        sgx_report_t report = { 0 };
        uint8_t nonce[ABAC_TEE_ATTESTATION_NONCE_SIZE];
        uint8_t *quote = NULL;
        uint32_t quote_size = 0;
        int enclave_status = ABAC_TEE_INVALID_REQUEST;
        sgx_status_t status;
        char quote_path[512];
        char quote_temp_path[512];
        char metadata_path[512];
        char metadata_temp_path[512];
        char nonce_hex[ABAC_TEE_ATTESTATION_NONCE_SIZE * 2 + 1];
        char metadata[1024];
        int metadata_size;
        uint32_t i;
        int result = -1;

        if (!output_directory || !policy_generation)
                return -1;

        if (mkdir(output_directory, 0700) != 0 && errno != EEXIST) {
                perror("create attestation directory");
                return -1;
        }

        status = sgx_init_quote(&target_info, &group_id);
        if (status != SGX_SUCCESS) {
                fprintf(stderr, "sgx_init_quote failed: 0x%04x\n", status);
                return -1;
        }

        if (random_nonce(nonce) != 0)
                return -1;

        status = ecall_create_attestation_report(
                enclave_id, &enclave_status,
                (const uint8_t *)&target_info, sizeof(target_info),
                nonce, sizeof(nonce),
                (uint8_t *)&report, sizeof(report));

        if (status != SGX_SUCCESS || enclave_status != ABAC_TEE_SUCCESS) {
                fprintf(stderr,
                        "Create attestation report failed: SGX=0x%x enclave=%d\n",
                        status, enclave_status);
                return -1;
        }

        status = sgx_calc_quote_size(NULL, 0, &quote_size);
        if (status != SGX_SUCCESS || !quote_size) {
                fprintf(stderr, "sgx_calc_quote_size failed: 0x%04x\n", status);
                return -1;
        }

        quote = calloc(1, quote_size);
        if (!quote)
                return -1;

        status = sgx_get_quote(&report, SGX_UNLINKABLE_SIGNATURE, &spid,
                               NULL, NULL, 0, NULL,
                               (sgx_quote_t *)quote, quote_size);

        if (status != SGX_SUCCESS) {
                fprintf(stderr, "sgx_get_quote failed: 0x%04x\n", status);
                goto out;
        }

        if (make_path(quote_path, sizeof(quote_path),
                      output_directory, QUOTE_FILE) != 0 ||
            make_path(quote_temp_path, sizeof(quote_temp_path),
                      output_directory, QUOTE_TEMP_FILE) != 0 ||
            make_path(metadata_path, sizeof(metadata_path),
                      output_directory, METADATA_FILE) != 0 ||
            make_path(metadata_temp_path, sizeof(metadata_temp_path),
                      output_directory, METADATA_TEMP_FILE) != 0)
                goto out;

        if (write_atomic_file(quote_path, quote_temp_path,
                              quote, quote_size) != 0) {
                perror("write attestation quote");
                goto out;
        }

        for (i = 0; i < ABAC_TEE_ATTESTATION_NONCE_SIZE; i++)
                snprintf(nonce_hex + i * 2, 3, "%02x", nonce[i]);

        metadata_size = snprintf(
                metadata, sizeof(metadata),
                "format=SGX_EPID\n"
                "hardware=%d\n"
                "verified=0\n"
                "policy_generation=%llu\n"
                "epid_group_id=%02x%02x%02x%02x\n"
                "nonce=%s\n"
                "quote_size=%u\n"
                "report_data_version=%u\n",
                ATTESTATION_HARDWARE,
                (unsigned long long)policy_generation,
                group_id[0], group_id[1], group_id[2], group_id[3],
                nonce_hex, quote_size,
                ABAC_TEE_ATTESTATION_DATA_VERSION);

        if (metadata_size < 0 ||
            (size_t)metadata_size >= sizeof(metadata) ||
            write_atomic_file(metadata_path, metadata_temp_path,
                              (const uint8_t *)metadata,
                              (size_t)metadata_size) != 0) {
                perror("write attestation metadata");
                unlink(quote_path);
                goto out;
        }

        printf("Attestation quote written to %s (%u bytes, hardware=%d)\n",
               quote_path, quote_size, ATTESTATION_HARDWARE);
        result = 0;

out:
        free(quote);
        return result;
}
