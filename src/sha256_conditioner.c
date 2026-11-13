#include "sha256_conditioner.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

void lh_secure_zero(volatile void *p, size_t n) {
    if (!p) return;
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) {
        *v++ = 0;
    }
}

size_t von_neumann_extract_bits(const uint8_t *raw_in, size_t raw_bytes, uint8_t *out_buf, size_t max_out_bytes) {
    if (!raw_in || !out_buf || raw_bytes == 0 || max_out_bytes == 0) return 0;

    memset(out_buf, 0, max_out_bytes);
    size_t out_bit_idx = 0;
    size_t max_bits = max_out_bytes * 8;

    for (size_t byte_idx = 0; byte_idx < raw_bytes; byte_idx++) {
        uint8_t byte = raw_in[byte_idx];
        /* Process 4 non-overlapping bit pairs: (b7,b6), (b5,b4), (b3,b2), (b1,b0) */
        for (int p = 6; p >= 0; p -= 2) {
            uint8_t b1 = (byte >> (p + 1)) & 0x01;
            uint8_t b0 = (byte >> p) & 0x01;

            if (b1 != b0) {
                /* 0,1 -> 0 ; 1,0 -> 1 */
                uint8_t extracted = (b1 == 1 && b0 == 0) ? 1 : 0;
                if (out_bit_idx < max_bits) {
                    size_t target_byte = out_bit_idx / 8;
                    size_t bit_pos = 7 - (out_bit_idx % 8);
                    if (extracted) {
                        out_buf[target_byte] |= (uint8_t)(1 << bit_pos);
                    }
                    out_bit_idx++;
                }
            }
        }
    }

    return (out_bit_idx + 7) / 8;
}

static inline uint32_t ror32(uint32_t v, unsigned int s) {
    return (v >> s) | (v << (32 - s));
}

static inline uint32_t fips_ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

static inline uint32_t fips_maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static inline uint32_t fips_sigma0(uint32_t x) {
    return ror32(x, 2) ^ ror32(x, 13) ^ ror32(x, 22);
}

static inline uint32_t fips_sigma1(uint32_t x) {
    return ror32(x, 6) ^ ror32(x, 11) ^ ror32(x, 25);
}

static inline uint32_t fips_gamma0(uint32_t x) {
    return ror32(x, 7) ^ ror32(x, 18) ^ (x >> 3);
}

static inline uint32_t fips_gamma1(uint32_t x) {
    return ror32(x, 17) ^ ror32(x, 19) ^ (x >> 10);
}

static const uint32_t sha256_k_constants[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

static void sha256_transform_block(lh_sha256_ctx_t *ctx, const uint8_t block[64]) {
    uint32_t w[64];

    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }

    for (int i = 16; i < 64; i++) {
        w[i] = fips_gamma1(w[i - 2]) + w[i - 7] + fips_gamma0(w[i - 15]) + w[i - 16];
    }

    uint32_t a = ctx->state[0];
    uint32_t b = ctx->state[1];
    uint32_t c = ctx->state[2];
    uint32_t d = ctx->state[3];
    uint32_t e = ctx->state[4];
    uint32_t f = ctx->state[5];
    uint32_t g = ctx->state[6];
    uint32_t h = ctx->state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + fips_sigma1(e) + fips_ch(e, f, g) + sha256_k_constants[i] + w[i];
        uint32_t t2 = fips_sigma0(a) + fips_maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;

    lh_secure_zero(w, sizeof(w));
}

void lh_sha256_init(lh_sha256_ctx_t *ctx) {
    if (!ctx) return;
    ctx->state[0] = 0x6a09e667U;
    ctx->state[1] = 0xbb67ae85U;
    ctx->state[2] = 0x3c6ef372U;
    ctx->state[3] = 0xa54ff53aU;
    ctx->state[4] = 0x510e527fU;
    ctx->state[5] = 0x9b05688cU;
    ctx->state[6] = 0x1f83d9abU;
    ctx->state[7] = 0x5be0cd19U;
    ctx->count = 0;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

void lh_sha256_update(lh_sha256_ctx_t *ctx, const uint8_t *data, size_t len) {
    if (!ctx || !data || len == 0) return;

    size_t buf_idx = (size_t)(ctx->count & 0x3f);
    ctx->count += len;

    size_t data_offset = 0;
    if (buf_idx > 0) {
        size_t needed = 64 - buf_idx;
        if (len < needed) {
            memcpy(ctx->buffer + buf_idx, data, len);
            return;
        }
        memcpy(ctx->buffer + buf_idx, data, needed);
        sha256_transform_block(ctx, ctx->buffer);
        data_offset += needed;
        len -= needed;
    }

    while (len >= 64) {
        sha256_transform_block(ctx, data + data_offset);
        data_offset += 64;
        len -= 64;
    }

    if (len > 0) {
        memcpy(ctx->buffer, data + data_offset, len);
    }
}

void lh_sha256_final(lh_sha256_ctx_t *ctx, uint8_t digest[LH_ENT_SHA256_DIGEST_SIZE]) {
    if (!ctx || !digest) return;

    uint64_t total_bits = ctx->count * 8ULL;
    size_t buf_idx = (size_t)(ctx->count & 0x3f);

    ctx->buffer[buf_idx++] = 0x80;
    if (buf_idx > 56) {
        memset(ctx->buffer + buf_idx, 0, 64 - buf_idx);
        sha256_transform_block(ctx, ctx->buffer);
        buf_idx = 0;
    }
    memset(ctx->buffer + buf_idx, 0, 56 - buf_idx);

    for (int i = 0; i < 8; i++) {
        ctx->buffer[56 + i] = (uint8_t)((total_bits >> ((7 - i) * 8)) & 0xff);
    }
    sha256_transform_block(ctx, ctx->buffer);

    for (int i = 0; i < 8; i++) {
        digest[i * 4] = (uint8_t)((ctx->state[i] >> 24) & 0xff);
        digest[i * 4 + 1] = (uint8_t)((ctx->state[i] >> 16) & 0xff);
        digest[i * 4 + 2] = (uint8_t)((ctx->state[i] >> 8) & 0xff);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i] & 0xff);
    }

    lh_secure_zero(ctx, sizeof(lh_sha256_ctx_t));
}

void lh_sha256_hash(const uint8_t *data, size_t len, uint8_t digest[LH_ENT_SHA256_DIGEST_SIZE]) {
    lh_sha256_ctx_t ctx;
    lh_sha256_init(&ctx);
    lh_sha256_update(&ctx, data, len);
    lh_sha256_final(&ctx, digest);
}

void lh_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t out[LH_ENT_SHA256_DIGEST_SIZE]) {
    uint8_t k_pad[64];
    memset(k_pad, 0, sizeof(k_pad));

    if (key_len > 64) {
        lh_sha256_hash(key, key_len, k_pad);
    } else {
        memcpy(k_pad, key, key_len);
    }

    uint8_t i_key_pad[64];
    uint8_t o_key_pad[64];
    for (int i = 0; i < 64; i++) {
        i_key_pad[i] = k_pad[i] ^ 0x36;
        o_key_pad[i] = k_pad[i] ^ 0x5c;
    }

    uint8_t inner_hash[LH_ENT_SHA256_DIGEST_SIZE];
    lh_sha256_ctx_t inner_ctx;
    lh_sha256_init(&inner_ctx);
    lh_sha256_update(&inner_ctx, i_key_pad, 64);
    lh_sha256_update(&inner_ctx, data, data_len);
    lh_sha256_final(&inner_ctx, inner_hash);

    lh_sha256_ctx_t outer_ctx;
    lh_sha256_init(&outer_ctx);
    lh_sha256_update(&outer_ctx, o_key_pad, 64);
    lh_sha256_update(&outer_ctx, inner_hash, LH_ENT_SHA256_DIGEST_SIZE);
    lh_sha256_final(&outer_ctx, out);

    lh_secure_zero(k_pad, sizeof(k_pad));
    lh_secure_zero(i_key_pad, sizeof(i_key_pad));
    lh_secure_zero(o_key_pad, sizeof(o_key_pad));
    lh_secure_zero(inner_hash, sizeof(inner_hash));
}

int condition_entropy_block(const uint8_t *raw_noise, size_t raw_len, double h_min, double credit_derating, conditioned_block_t *block) {
    if (!raw_noise || raw_len < 64 || !block) return -1;
    memset(block, 0, sizeof(conditioned_block_t));

    /* Mix high-resolution timestamp with raw noise */
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    lh_sha256_ctx_t ctx;
    lh_sha256_init(&ctx);
    lh_sha256_update(&ctx, (const uint8_t *)&ts, sizeof(ts));
    lh_sha256_update(&ctx, raw_noise, raw_len);
    lh_sha256_final(&ctx, block->digest);

    block->raw_bytes_consumed = (uint32_t)raw_len;

    /* Conservative Entropy Credit Formula */
    double derating = (credit_derating > 0.0 && credit_derating <= 1.0) ? credit_derating : 0.50;
    double raw_entropy_bits = (double)raw_len * h_min * derating;
    int credited = (int)floor(raw_entropy_bits);
    if (credited > 256) credited = 256;
    if (credited < 1) credited = 1;
    block->credited_entropy_bits = credited;

    /* Populate Linux rand_pool_info */
    block->pool_info.entropy_count = credited;
    block->pool_info.buf_size = 32;
    for (int i = 0; i < 8; i++) {
        block->pool_info.buf[i] = ((uint32_t)block->digest[i * 4] << 24) |
                                  ((uint32_t)block->digest[i * 4 + 1] << 16) |
                                  ((uint32_t)block->digest[i * 4 + 2] << 8) |
                                  ((uint32_t)block->digest[i * 4 + 3]);
    }

    return 0;
}

bool sha256_startup_kat(void) {
    /* FIPS 180-4 test vector: "abc" */
    static const uint8_t expected[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };

    uint8_t out[32];
    lh_sha256_hash((const uint8_t *)"abc", 3, out);

    int diff = 0;
    for (int i = 0; i < 32; i++) {
        diff |= (out[i] ^ expected[i]);
    }

    lh_secure_zero(out, sizeof(out));
    return (diff == 0);
}
