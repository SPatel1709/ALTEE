#ifndef ABAC_TEE_ATTESTATION_H
#define ABAC_TEE_ATTESTATION_H

#include <stdint.h>
#include <sgx_urts.h>

int generate_attestation_quote(sgx_enclave_id_t enclave_id,
                               uint64_t policy_generation,
                               const char *output_directory);

#endif
