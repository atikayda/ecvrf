/* CLI wrapper for ECVRF C implementation — cross-validation use only. */
#include "ecvrf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hex_char(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static size_t hex_decode(const char *hex, uint8_t *out, size_t max_len)
{
    size_t hex_len = strlen(hex);
    size_t byte_len = hex_len / 2;
    if (byte_len > max_len) return 0;
    for (size_t i = 0; i < byte_len; i++) {
        int hi = hex_char(hex[2 * i]);
        int lo = hex_char(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return byte_len;
}

static void hex_encode(const uint8_t *data, size_t len, char *out)
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i]     = hex[data[i] >> 4];
        out[2 * i + 1] = hex[data[i] & 0x0f];
    }
    out[2 * len] = '\0';
}

static char *read_alpha(int argc, char **argv, int idx)
{
    if (idx < argc && strcmp(argv[idx], "--alpha-file") == 0 && idx + 1 < argc) {
        FILE *f = fopen(argv[idx + 1], "r");
        if (!f) { fprintf(stderr, "cannot open alpha file: %s\n", argv[idx + 1]); exit(1); }
        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        fseek(f, 0, SEEK_SET);
        char *buf = malloc(sz + 1);
        size_t n = fread(buf, 1, sz, f);
        fclose(f);
        buf[n] = '\0';
        while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' || buf[n - 1] == ' '))
            buf[--n] = '\0';
        return buf;
    }
    if (idx < argc)
        return argv[idx];
    fprintf(stderr, "missing alpha argument\n");
    exit(1);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: ecvrf-c prove|verify ...\n");
        return 1;
    }

    if (strcmp(argv[1], "prove") == 0) {
        if (argc < 4) {
            fprintf(stderr, "usage: ecvrf-c prove <sk_hex> <alpha_hex|--alpha-file path>\n");
            return 1;
        }
        uint8_t sk[32];
        if (hex_decode(argv[2], sk, 32) != 32) {
            fprintf(stderr, "invalid sk hex\n"); return 1;
        }
        char *alpha_hex = read_alpha(argc, argv, 3);
        size_t alpha_len = strlen(alpha_hex) / 2;
        uint8_t *alpha = malloc(alpha_len);
        if (hex_decode(alpha_hex, alpha, alpha_len) != alpha_len) {
            fprintf(stderr, "invalid alpha hex\n"); return 1;
        }
        uint8_t pi[81];
        if (ecvrf_prove(sk, alpha, alpha_len, pi) != 0) {
            fprintf(stderr, "prove failed\n"); free(alpha); return 1;
        }
        uint8_t beta[32];
        if (ecvrf_proof_to_hash(pi, 81, beta) != 0) {
            fprintf(stderr, "proof_to_hash failed\n"); free(alpha); return 1;
        }
        char pi_hex[163], beta_hex[65];
        hex_encode(pi, 81, pi_hex);
        hex_encode(beta, 32, beta_hex);
        printf("{\"pi\":\"%s\",\"beta\":\"%s\"}\n", pi_hex, beta_hex);
        free(alpha);
    } else if (strcmp(argv[1], "verify") == 0) {
        if (argc < 5) {
            fprintf(stderr, "usage: ecvrf-c verify <pk_hex> <pi_hex> <alpha_hex|--alpha-file path>\n");
            return 1;
        }
        uint8_t pk[33];
        if (hex_decode(argv[2], pk, 33) != 33) {
            fprintf(stderr, "invalid pk hex\n"); return 1;
        }
        uint8_t pi[81];
        if (hex_decode(argv[3], pi, 81) != 81) {
            fprintf(stderr, "invalid pi hex\n"); return 1;
        }
        char *alpha_hex = read_alpha(argc, argv, 4);
        size_t alpha_len = strlen(alpha_hex) / 2;
        uint8_t *alpha = malloc(alpha_len);
        if (hex_decode(alpha_hex, alpha, alpha_len) != alpha_len) {
            fprintf(stderr, "invalid alpha hex\n"); return 1;
        }
        uint8_t beta[32];
        int valid = ecvrf_verify(pk, pi, 81, alpha, alpha_len, beta);
        if (valid) {
            char beta_hex[65];
            hex_encode(beta, 32, beta_hex);
            printf("{\"valid\":true,\"beta\":\"%s\"}\n", beta_hex);
        } else {
            printf("{\"valid\":false,\"beta\":null}\n");
        }
        free(alpha);
    } else {
        fprintf(stderr, "unknown command: %s\n", argv[1]);
        return 1;
    }
    return 0;
}
