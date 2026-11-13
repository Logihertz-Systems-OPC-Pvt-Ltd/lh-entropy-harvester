#ifndef LH_SHA256_CONDITIONER_H
#define LH_SHA256_CONDITIONER_H

#include "entropy_types.h"

/* Secure Buffer Zeroization */
void lh_secure_zero(volatile void *p, size_t n);

/* Von Neumann Unbiased Bit Extractor */
size_t von_neumann_extract_bits(const uint8_t *raw_in, size_t raw_bytes, uint8_t *out_buf, size_t max_out_bytes);

/* FIPS 180-4 SHA-256 Implementation */
typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[64];
} lh_sha256_ctx_t;

void lh_sha256_init(lh_sha256_ctx_t *ctx);
void lh_sha256_update(lh_sha256_ctx_t *ctx, const uint8_t *data, size_t len);
void lh_sha256_final(lh_sha256_ctx_t *ctx, uint8_t digest[LH_ENT_SHA256_DIGEST_SIZE]);
void lh_sha256_hash(const uint8_t *data, size_t len, uint8_t digest[LH_ENT_SHA256_DIGEST_SIZE]);

/* RFC 2104 HMAC-SHA256 */
void lh_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t out[LH_ENT_SHA256_DIGEST_SIZE]);

/* NIST SP 800-90B Cryptographic Conditioning */
int condition_entropy_block(const uint8_t *raw_noise, size_t raw_len, double h_min, double credit_derating, conditioned_block_t *block);

/* FIPS 140-3 Known Answer Test (KAT) */
bool sha256_startup_kat(void);

#endif /* LH_SHA256_CONDITIONER_H */
