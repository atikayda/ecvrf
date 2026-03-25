#ifndef ECVRF_SECP256K1_SHA256_TAI_H
#define ECVRF_SECP256K1_SHA256_TAI_H

#include <stddef.h>
#include <stdint.h>

#define ECVRF_PROOF_LEN 81
#define ECVRF_BETA_LEN  32
#define ECVRF_SK_LEN    32
#define ECVRF_PK_LEN    33

/* Generate an 81-byte VRF proof. Returns 0 on success, -1 on error. */
int ecvrf_prove(const uint8_t sk[32],
                const uint8_t *alpha, size_t alpha_len,
                uint8_t pi_out[81]);

/* Verify a VRF proof. Returns 1 if valid (fills beta_out), 0 if invalid. */
int ecvrf_verify(const uint8_t pk[33],
                 const uint8_t *pi, size_t pi_len,
                 const uint8_t *alpha, size_t alpha_len,
                 uint8_t beta_out[32]);

/* Extract VRF output (beta) from a proof. Returns 0 on success, -1 on error. */
int ecvrf_proof_to_hash(const uint8_t *pi, size_t pi_len,
                        uint8_t beta_out[32]);

/* Derive compressed public key from secret key. Returns 0 on success, -1 on error. */
int ecvrf_derive_pk(const uint8_t sk[32], uint8_t pk_out[33]);

#endif
