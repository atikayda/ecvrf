/* Test runner for ECVRF-SECP256K1-SHA256-TAI C implementation. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ecvrf.h"
#include "vectors_data.h"

static int g_pass;
static int g_fail;

static void pass(const char *name) { g_pass++; (void)name; }
static void fail(const char *name, const char *msg)
{
    fprintf(stderr, "FAIL [%s]: %s\n", name, msg);
    g_fail++;
}

static uint8_t *hex_decode(const char *hex, size_t *out_len)
{
    size_t slen = strlen(hex);
    if (slen % 2 != 0) return NULL;
    *out_len = slen / 2;
    if (*out_len == 0) {
        uint8_t *empty = malloc(1);
        return empty;
    }
    uint8_t *buf = malloc(*out_len);
    if (!buf) return NULL;
    for (size_t i = 0; i < *out_len; i++) {
        unsigned int b;
        if (sscanf(hex + 2 * i, "%02x", &b) != 1) { free(buf); return NULL; }
        buf[i] = (uint8_t)b;
    }
    return buf;
}

static char *hex_encode(const uint8_t *data, size_t len)
{
    char *out = malloc(len * 2 + 1);
    if (!out) return NULL;
    for (size_t i = 0; i < len; i++)
        sprintf(out + 2 * i, "%02x", data[i]);
    out[len * 2] = '\0';
    return out;
}

/* ------------------------------------------------------------------ */
/* prove tests                                                        */
/* ------------------------------------------------------------------ */

static void test_prove(void)
{
    for (size_t i = 0; i < NUM_TEST_VECTORS; i++) {
        const test_vector_t *v = &TEST_VECTORS[i];
        size_t sk_len, alpha_len;
        uint8_t *sk    = hex_decode(v->sk, &sk_len);
        uint8_t *alpha = hex_decode(v->alpha, &alpha_len);
        uint8_t pi[ECVRF_PROOF_LEN];

        int rc = ecvrf_prove(sk, alpha, alpha_len, pi);
        if (rc != 0) {
            fail(v->label, "prove returned error");
        } else {
            char *got = hex_encode(pi, ECVRF_PROOF_LEN);
            if (strcmp(got, v->pi) != 0) {
                char msg[256];
                snprintf(msg, sizeof(msg), "pi mismatch");
                fail(v->label, msg);
            } else {
                pass(v->label);
            }
            free(got);
        }

        free(sk);
        free(alpha);
    }
}

/* ------------------------------------------------------------------ */
/* verify tests                                                       */
/* ------------------------------------------------------------------ */

static void test_verify(void)
{
    for (size_t i = 0; i < NUM_TEST_VECTORS; i++) {
        const test_vector_t *v = &TEST_VECTORS[i];
        size_t pk_len, alpha_len, pi_len;
        uint8_t *pk    = hex_decode(v->pk, &pk_len);
        uint8_t *alpha = hex_decode(v->alpha, &alpha_len);
        uint8_t *pi    = hex_decode(v->pi, &pi_len);
        uint8_t beta[ECVRF_BETA_LEN];

        int valid = ecvrf_verify(pk, pi, pi_len, alpha, alpha_len, beta);
        if (!valid) {
            fail(v->label, "verify returned invalid for valid proof");
        } else {
            char *got = hex_encode(beta, ECVRF_BETA_LEN);
            if (strcmp(got, v->beta) != 0)
                fail(v->label, "verify beta mismatch");
            else
                pass(v->label);
            free(got);
        }

        free(pk);
        free(alpha);
        free(pi);
    }
}

/* ------------------------------------------------------------------ */
/* proof_to_hash tests                                                */
/* ------------------------------------------------------------------ */

static void test_proof_to_hash(void)
{
    for (size_t i = 0; i < NUM_TEST_VECTORS; i++) {
        const test_vector_t *v = &TEST_VECTORS[i];
        size_t pi_len;
        uint8_t *pi = hex_decode(v->pi, &pi_len);
        uint8_t beta[ECVRF_BETA_LEN];

        int rc = ecvrf_proof_to_hash(pi, pi_len, beta);
        if (rc != 0) {
            fail(v->label, "proof_to_hash error");
        } else {
            char *got = hex_encode(beta, ECVRF_BETA_LEN);
            if (strcmp(got, v->beta) != 0)
                fail(v->label, "proof_to_hash beta mismatch");
            else
                pass(v->label);
            free(got);
        }

        free(pi);
    }
}

/* ------------------------------------------------------------------ */
/* negative verify tests                                              */
/* ------------------------------------------------------------------ */

static void test_negative_verify(void)
{
    for (size_t i = 0; i < NUM_NEG_VECTORS; i++) {
        const neg_vector_t *v = &NEG_VECTORS[i];
        size_t pk_len, alpha_len, pi_len;
        uint8_t *pk    = hex_decode(v->pk, &pk_len);
        uint8_t *alpha = hex_decode(v->alpha, &alpha_len);
        uint8_t *pi    = hex_decode(v->pi, &pi_len);
        uint8_t beta[ECVRF_BETA_LEN];

        int valid = ecvrf_verify(pk, pi, pi_len, alpha, alpha_len, beta);
        if (valid != v->expected_verify) {
            char msg[128];
            snprintf(msg, sizeof(msg), "expected verify=%d, got %d",
                     v->expected_verify, valid);
            fail(v->description, msg);
        } else {
            pass(v->description);
        }

        free(pk);
        free(alpha);
        free(pi);
    }
}

/* ------------------------------------------------------------------ */
/* derive_pk tests                                                    */
/* ------------------------------------------------------------------ */

static void test_derive_pk(void)
{
    for (size_t i = 0; i < NUM_TEST_VECTORS; i++) {
        const test_vector_t *v = &TEST_VECTORS[i];
        size_t sk_len;
        uint8_t *sk = hex_decode(v->sk, &sk_len);
        uint8_t pk[ECVRF_PK_LEN];

        int rc = ecvrf_derive_pk(sk, pk);
        if (rc != 0) {
            fail(v->label, "derive_pk error");
        } else {
            char *got = hex_encode(pk, ECVRF_PK_LEN);
            if (strcmp(got, v->pk) != 0)
                fail(v->label, "derive_pk mismatch");
            else
                pass(v->label);
            free(got);
        }

        free(sk);
    }
}

/* ------------------------------------------------------------------ */
/* determinism test                                                   */
/* ------------------------------------------------------------------ */

static void test_determinism(void)
{
    if (NUM_TEST_VECTORS == 0) return;
    const test_vector_t *v = &TEST_VECTORS[0];
    size_t sk_len, alpha_len;
    uint8_t *sk    = hex_decode(v->sk, &sk_len);
    uint8_t *alpha = hex_decode(v->alpha, &alpha_len);
    uint8_t pi1[ECVRF_PROOF_LEN], pi2[ECVRF_PROOF_LEN];

    if (ecvrf_prove(sk, alpha, alpha_len, pi1) != 0 ||
        ecvrf_prove(sk, alpha, alpha_len, pi2) != 0) {
        fail("determinism", "prove failed");
    } else if (memcmp(pi1, pi2, ECVRF_PROOF_LEN) != 0) {
        fail("determinism", "two prove calls produced different proofs");
    } else {
        pass("determinism");
    }

    free(sk);
    free(alpha);
}

/* ------------------------------------------------------------------ */
/* main                                                               */
/* ------------------------------------------------------------------ */

int main(void)
{
    printf("=== ECVRF-SECP256K1-SHA256-TAI  C implementation tests ===\n\n");

    printf("--- prove (%zu vectors) ---\n", NUM_TEST_VECTORS);
    test_prove();

    printf("--- verify (%zu vectors) ---\n", NUM_TEST_VECTORS);
    test_verify();

    printf("--- proof_to_hash (%zu vectors) ---\n", NUM_TEST_VECTORS);
    test_proof_to_hash();

    printf("--- negative verify (%zu vectors) ---\n", NUM_NEG_VECTORS);
    test_negative_verify();

    printf("--- derive_pk (%zu vectors) ---\n", NUM_TEST_VECTORS);
    test_derive_pk();

    printf("--- determinism ---\n");
    test_determinism();

    printf("\n=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail > 0 ? 1 : 0;
}
