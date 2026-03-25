/* RFC 9381 ECVRF-SECP256K1-SHA256-TAI implementation using OpenSSL. */

#include "ecvrf.h"

#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <openssl/hmac.h>
#pragma GCC diagnostic pop

#define SUITE_BYTE 0xFE
#define COMP_LEN   33
#define CHAL_LEN   16
#define SCAL_LEN   32

/* ------------------------------------------------------------------ */
/* helpers                                                            */
/* ------------------------------------------------------------------ */

static void sha256(const uint8_t *data, size_t len, uint8_t out[32])
{
    unsigned int md_len = 32;
    EVP_Digest(data, len, out, &md_len, EVP_sha256(), NULL);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
static void hmac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len,
                        uint8_t out[32])
{
    unsigned int md_len = 32;
    HMAC(EVP_sha256(), key, (int)key_len, data, data_len, out, &md_len);
}
#pragma GCC diagnostic pop

static int pt_compress(const EC_GROUP *grp, const EC_POINT *pt,
                       uint8_t out[33], BN_CTX *ctx)
{
    return EC_POINT_point2oct(grp, pt, POINT_CONVERSION_COMPRESSED,
                              out, COMP_LEN, ctx) == COMP_LEN ? 0 : -1;
}

static EC_POINT *pt_decompress(const EC_GROUP *grp, const uint8_t *data,
                                size_t len, BN_CTX *ctx)
{
    EC_POINT *pt = EC_POINT_new(grp);
    if (!pt) return NULL;
    if (EC_POINT_oct2point(grp, pt, data, len, ctx) != 1) {
        EC_POINT_free(pt);
        return NULL;
    }
    return pt;
}

static void bn_to_32(const BIGNUM *bn, uint8_t out[32])
{
    memset(out, 0, 32);
    int n = BN_num_bytes(bn);
    if (n > 32) n = 32;
    BN_bn2bin(bn, out + (32 - n));
}

/* ------------------------------------------------------------------ */
/* encode_to_curve — RFC 9381 Section 5.4.1.1 (try_and_increment)     */
/* ------------------------------------------------------------------ */

static EC_POINT *encode_to_curve_tai(const EC_GROUP *grp,
                                      const uint8_t pk[33],
                                      const uint8_t *alpha, size_t alpha_len,
                                      BN_CTX *ctx)
{
    size_t prefix_len = 2 + COMP_LEN;
    size_t input_len  = prefix_len + alpha_len + 2;
    uint8_t *input = malloc(input_len);
    if (!input) return NULL;

    input[0] = SUITE_BYTE;
    input[1] = 0x01;
    memcpy(input + 2, pk, COMP_LEN);
    if (alpha_len > 0)
        memcpy(input + prefix_len, alpha, alpha_len);
    input[input_len - 1] = 0x00;

    for (int ctr = 0; ctr <= 255; ctr++) {
        input[input_len - 2] = (uint8_t)ctr;

        uint8_t hash[32];
        sha256(input, input_len, hash);

        uint8_t compressed[COMP_LEN];
        compressed[0] = 0x02;
        memcpy(compressed + 1, hash, 32);

        EC_POINT *pt = pt_decompress(grp, compressed, COMP_LEN, ctx);
        if (pt) {
            free(input);
            return pt;
        }
    }

    free(input);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* RFC 6979 nonce generation — RFC 9381 Section 5.4.2.1               */
/* ------------------------------------------------------------------ */

static BIGNUM *rfc6979_nonce(const uint8_t sk[32],
                              const EC_GROUP *grp,
                              const EC_POINT *h_point,
                              BN_CTX *ctx)
{
    uint8_t h_bytes[COMP_LEN];
    if (pt_compress(grp, h_point, h_bytes, ctx) != 0) return NULL;

    uint8_t h1[32];
    sha256(h_bytes, COMP_LEN, h1);

    const BIGNUM *order = EC_GROUP_get0_order(grp);

    /* bits2octets(h1) = (int(h1) mod n) as 32 bytes */
    uint8_t h1_mod[32];
    {
        BIGNUM *h1_bn   = BN_bin2bn(h1, 32, NULL);
        BIGNUM *reduced = BN_new();
        BN_nnmod(reduced, h1_bn, order, ctx);
        bn_to_32(reduced, h1_mod);
        BN_free(h1_bn);
        BN_free(reduced);
    }

    uint8_t V[32], K[32];
    memset(V, 0x01, 32);
    memset(K, 0x00, 32);

    /* Step d: K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1)) */
    uint8_t buf[97];
    memcpy(buf, V, 32);
    buf[32] = 0x00;
    memcpy(buf + 33, sk, 32);
    memcpy(buf + 65, h1_mod, 32);
    hmac_sha256(K, 32, buf, 97, K);

    /* Step e */
    hmac_sha256(K, 32, V, 32, V);

    /* Step f: K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1)) */
    memcpy(buf, V, 32);
    buf[32] = 0x01;
    memcpy(buf + 33, sk, 32);
    memcpy(buf + 65, h1_mod, 32);
    hmac_sha256(K, 32, buf, 97, K);

    /* Step g */
    hmac_sha256(K, 32, V, 32, V);

    /* Step h: loop until valid k found */
    BIGNUM *k = BN_new();
    for (int i = 0; i < 1000; i++) {
        hmac_sha256(K, 32, V, 32, V);
        BN_bin2bn(V, 32, k);

        if (!BN_is_zero(k) && BN_cmp(k, order) < 0)
            return k;

        uint8_t vpad[33];
        memcpy(vpad, V, 32);
        vpad[32] = 0x00;
        hmac_sha256(K, 32, vpad, 33, K);
        hmac_sha256(K, 32, V, 32, V);
    }

    BN_free(k);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* challenge_generation — RFC 9381 Section 5.4.3 (5-point)            */
/* ------------------------------------------------------------------ */

static BIGNUM *challenge_generation(const EC_GROUP *grp,
                                     const EC_POINT *Y,
                                     const EC_POINT *H,
                                     const EC_POINT *Gamma,
                                     const EC_POINT *U,
                                     const EC_POINT *V,
                                     BN_CTX *ctx)
{
    uint8_t input[2 + 5 * COMP_LEN + 1];
    input[0] = SUITE_BYTE;
    input[1] = 0x02;

    uint8_t *p = input + 2;
    if (pt_compress(grp, Y,     p, ctx) != 0) return NULL; p += COMP_LEN;
    if (pt_compress(grp, H,     p, ctx) != 0) return NULL; p += COMP_LEN;
    if (pt_compress(grp, Gamma, p, ctx) != 0) return NULL; p += COMP_LEN;
    if (pt_compress(grp, U,     p, ctx) != 0) return NULL; p += COMP_LEN;
    if (pt_compress(grp, V,     p, ctx) != 0) return NULL; p += COMP_LEN;
    *p = 0x00;

    uint8_t hash[32];
    sha256(input, sizeof(input), hash);

    return BN_bin2bn(hash, CHAL_LEN, NULL);
}

/* ------------------------------------------------------------------ */
/* proof_to_hash — RFC 9381 Section 5.2                               */
/* ------------------------------------------------------------------ */

static int proof_to_hash_int(const EC_GROUP *grp, const EC_POINT *gamma,
                              uint8_t beta[32], BN_CTX *ctx)
{
    uint8_t input[2 + COMP_LEN + 1];
    input[0] = SUITE_BYTE;
    input[1] = 0x03;
    if (pt_compress(grp, gamma, input + 2, ctx) != 0) return -1;
    input[2 + COMP_LEN] = 0x00;

    sha256(input, sizeof(input), beta);
    return 0;
}

/* ------------------------------------------------------------------ */
/* decode_proof                                                       */
/* ------------------------------------------------------------------ */

static int decode_proof(const EC_GROUP *grp, const uint8_t *pi, size_t pi_len,
                        EC_POINT **gamma_out, BIGNUM **c_out, BIGNUM **s_out,
                        BN_CTX *ctx)
{
    if (pi_len != ECVRF_PROOF_LEN) return -1;

    EC_POINT *gamma = pt_decompress(grp, pi, COMP_LEN, ctx);
    if (!gamma) return -1;

    BIGNUM *c = BN_bin2bn(pi + COMP_LEN, CHAL_LEN, NULL);
    if (!c) { EC_POINT_free(gamma); return -1; }

    BIGNUM *s = BN_bin2bn(pi + COMP_LEN + CHAL_LEN, SCAL_LEN, NULL);
    if (!s) { EC_POINT_free(gamma); BN_free(c); return -1; }

    *gamma_out = gamma;
    *c_out     = c;
    *s_out     = s;
    return 0;
}

/* ------------------------------------------------------------------ */
/* public API                                                         */
/* ------------------------------------------------------------------ */

int ecvrf_prove(const uint8_t sk[32],
                const uint8_t *alpha, size_t alpha_len,
                uint8_t pi_out[81])
{
    int ret = -1;
    EC_GROUP *grp = NULL;
    BN_CTX   *ctx = NULL;
    BIGNUM   *x = NULL, *k = NULL, *c = NULL, *s = NULL, *cx = NULL;
    EC_POINT *Y = NULL, *H = NULL, *Gamma = NULL, *U = NULL, *V = NULL;

    grp = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!grp) goto out;
    ctx = BN_CTX_new();
    if (!ctx) goto out;

    x = BN_bin2bn(sk, 32, NULL);
    if (!x || BN_is_zero(x)) goto out;

    const BIGNUM *order = EC_GROUP_get0_order(grp);
    if (BN_cmp(x, order) >= 0) goto out;

    Y = EC_POINT_new(grp);
    if (!Y || EC_POINT_mul(grp, Y, x, NULL, NULL, ctx) != 1) goto out;

    uint8_t pk_bytes[COMP_LEN];
    if (pt_compress(grp, Y, pk_bytes, ctx) != 0) goto out;

    H = encode_to_curve_tai(grp, pk_bytes, alpha, alpha_len, ctx);
    if (!H) goto out;

    Gamma = EC_POINT_new(grp);
    if (!Gamma || EC_POINT_mul(grp, Gamma, NULL, H, x, ctx) != 1) goto out;

    k = rfc6979_nonce(sk, grp, H, ctx);
    if (!k) goto out;

    U = EC_POINT_new(grp);
    if (!U || EC_POINT_mul(grp, U, k, NULL, NULL, ctx) != 1) goto out;

    V = EC_POINT_new(grp);
    if (!V || EC_POINT_mul(grp, V, NULL, H, k, ctx) != 1) goto out;

    c = challenge_generation(grp, Y, H, Gamma, U, V, ctx);
    if (!c) goto out;

    cx = BN_new();
    s  = BN_new();
    if (!cx || !s) goto out;
    BN_mul(cx, c, x, ctx);
    BN_add(s, k, cx);
    BN_nnmod(s, s, order, ctx);

    if (pt_compress(grp, Gamma, pi_out, ctx) != 0) goto out;

    uint8_t c32[32];
    bn_to_32(c, c32);
    memcpy(pi_out + COMP_LEN, c32 + 16, CHAL_LEN);

    bn_to_32(s, pi_out + COMP_LEN + CHAL_LEN);

    ret = 0;
out:
    EC_POINT_free(Y);
    EC_POINT_free(H);
    EC_POINT_free(Gamma);
    EC_POINT_free(U);
    EC_POINT_free(V);
    BN_free(x);
    BN_free(k);
    BN_free(c);
    BN_free(s);
    BN_free(cx);
    BN_CTX_free(ctx);
    EC_GROUP_free(grp);
    return ret;
}

int ecvrf_verify(const uint8_t pk[33],
                 const uint8_t *pi, size_t pi_len,
                 const uint8_t *alpha, size_t alpha_len,
                 uint8_t beta_out[32])
{
    int ret = 0;
    EC_GROUP *grp = NULL;
    BN_CTX   *ctx = NULL;
    EC_POINT *Gamma = NULL, *Y = NULL, *H = NULL;
    EC_POINT *U = NULL, *V_pt = NULL, *sH = NULL, *ncG = NULL;
    BIGNUM   *c = NULL, *s = NULL, *neg_c = NULL, *c_prime = NULL;

    grp = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!grp) goto out;
    ctx = BN_CTX_new();
    if (!ctx) goto out;

    if (decode_proof(grp, pi, pi_len, &Gamma, &c, &s, ctx) != 0) goto out;

    const BIGNUM *order = EC_GROUP_get0_order(grp);
    if (BN_cmp(s, order) >= 0) goto out;

    {
        BIGNUM *max_c = BN_new();
        BN_set_bit(max_c, 128);
        int over = BN_cmp(c, max_c) >= 0;
        BN_free(max_c);
        if (over) goto out;
    }

    Y = pt_decompress(grp, pk, COMP_LEN, ctx);
    if (!Y) goto out;

    uint8_t pk_copy[COMP_LEN];
    memcpy(pk_copy, pk, COMP_LEN);
    H = encode_to_curve_tai(grp, pk_copy, alpha, alpha_len, ctx);
    if (!H) goto out;

    neg_c = BN_new();
    if (!neg_c) goto out;
    BN_sub(neg_c, order, c);

    /* U = s*G + (-c)*Y */
    U = EC_POINT_new(grp);
    if (!U || EC_POINT_mul(grp, U, s, Y, neg_c, ctx) != 1) goto out;

    /* V = s*H + (-c)*Gamma */
    sH  = EC_POINT_new(grp);
    ncG = EC_POINT_new(grp);
    V_pt = EC_POINT_new(grp);
    if (!sH || !ncG || !V_pt) goto out;
    if (EC_POINT_mul(grp, sH,  NULL, H,     s,     ctx) != 1) goto out;
    if (EC_POINT_mul(grp, ncG, NULL, Gamma,  neg_c, ctx) != 1) goto out;
    if (EC_POINT_add(grp, V_pt, sH, ncG, ctx) != 1) goto out;

    c_prime = challenge_generation(grp, Y, H, Gamma, U, V_pt, ctx);
    if (!c_prime) goto out;

    if (BN_cmp(c, c_prime) == 0) {
        if (proof_to_hash_int(grp, Gamma, beta_out, ctx) == 0)
            ret = 1;
    }

out:
    EC_POINT_free(Gamma);
    EC_POINT_free(Y);
    EC_POINT_free(H);
    EC_POINT_free(U);
    EC_POINT_free(V_pt);
    EC_POINT_free(sH);
    EC_POINT_free(ncG);
    BN_free(c);
    BN_free(s);
    BN_free(neg_c);
    BN_free(c_prime);
    BN_CTX_free(ctx);
    EC_GROUP_free(grp);
    return ret;
}

int ecvrf_proof_to_hash(const uint8_t *pi, size_t pi_len,
                        uint8_t beta_out[32])
{
    if (pi_len != ECVRF_PROOF_LEN) return -1;

    EC_GROUP *grp = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!grp) return -1;
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) { EC_GROUP_free(grp); return -1; }

    EC_POINT *gamma = pt_decompress(grp, pi, COMP_LEN, ctx);
    if (!gamma) {
        BN_CTX_free(ctx);
        EC_GROUP_free(grp);
        return -1;
    }

    int rc = proof_to_hash_int(grp, gamma, beta_out, ctx);

    EC_POINT_free(gamma);
    BN_CTX_free(ctx);
    EC_GROUP_free(grp);
    return rc;
}

int ecvrf_derive_pk(const uint8_t sk[32], uint8_t pk_out[33])
{
    int ret = -1;
    EC_GROUP *grp = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!grp) return -1;
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) { EC_GROUP_free(grp); return -1; }

    BIGNUM *x = BN_bin2bn(sk, 32, NULL);
    if (!x || BN_is_zero(x)) goto out;

    const BIGNUM *order = EC_GROUP_get0_order(grp);
    if (BN_cmp(x, order) >= 0) goto out;

    EC_POINT *Y = EC_POINT_new(grp);
    if (!Y || EC_POINT_mul(grp, Y, x, NULL, NULL, ctx) != 1) {
        EC_POINT_free(Y);
        goto out;
    }

    ret = pt_compress(grp, Y, pk_out, ctx);
    EC_POINT_free(Y);

out:
    BN_free(x);
    BN_CTX_free(ctx);
    EC_GROUP_free(grp);
    return ret;
}
