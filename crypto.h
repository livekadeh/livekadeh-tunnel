#ifndef LIVEKADEH_CRYPTO_H
#define LIVEKADEH_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

/* SHA-256 Implementation */
typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[64];
} lk_sha256_ctx;

static inline uint32_t lk_rotr32(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

#define LK_CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define LK_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define LK_EP0(x)       (lk_rotr32(x, 2) ^ lk_rotr32(x, 13) ^ lk_rotr32(x, 22))
#define LK_EP1(x)       (lk_rotr32(x, 6) ^ lk_rotr32(x, 11) ^ lk_rotr32(x, 25))
#define LK_SIG0(x)      (lk_rotr32(x, 7) ^ lk_rotr32(x, 18) ^ ((x) >> 3))
#define LK_SIG1(x)      (lk_rotr32(x, 17) ^ lk_rotr32(x, 19) ^ ((x) >> 10))

static const uint32_t lk_k256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static inline void lk_sha256_transform(lk_sha256_ctx *ctx, const uint8_t data[64]) {
    uint32_t a, b, c, d, e, f, g, h, t1, t2, m[64];
    int i;

    for (i = 0; i < 16; ++i) {
        m[i] = ((uint32_t)data[i * 4] << 24) |
               ((uint32_t)data[i * 4 + 1] << 16) |
               ((uint32_t)data[i * 4 + 2] << 8) |
               ((uint32_t)data[i * 4 + 3]);
    }
    for (; i < 64; ++i) {
        m[i] = LK_SIG1(m[i - 2]) + m[i - 7] + LK_SIG0(m[i - 15]) + m[i - 16];
    }

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + LK_EP1(e) + LK_CH(e, f, g) + lk_k256[i] + m[i];
        t2 = LK_EP0(a) + LK_MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static inline void lk_sha256_init(lk_sha256_ctx *ctx) {
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
}

static inline void lk_sha256_update(lk_sha256_ctx *ctx, const uint8_t *data, size_t len) {
    size_t i = 0;
    size_t buffer_idx = (size_t)(ctx->count & 63);
    ctx->count += len;

    if (buffer_idx > 0) {
        size_t copy_len = 64 - buffer_idx;
        if (len < copy_len) {
            memcpy(&ctx->buffer[buffer_idx], data, len);
            return;
        }
        memcpy(&ctx->buffer[buffer_idx], data, copy_len);
        lk_sha256_transform(ctx, ctx->buffer);
        i += copy_len;
    }

    for (; i + 64 <= len; i += 64) {
        lk_sha256_transform(ctx, &data[i]);
    }

    if (i < len) {
        memcpy(ctx->buffer, &data[i], len - i);
    }
}

static inline void lk_sha256_final(lk_sha256_ctx *ctx, uint8_t hash[32]) {
    uint8_t pad[64];
    size_t pad_len;
    uint64_t total_bits;
    int i;

    pad[0] = 0x80;
    memset(pad + 1, 0, 63);

    size_t buffer_idx = (size_t)(ctx->count & 63);
    if (buffer_idx < 56) {
        pad_len = 56 - buffer_idx;
    } else {
        pad_len = 120 - buffer_idx;
    }

    total_bits = ctx->count * 8;
    lk_sha256_update(ctx, pad, pad_len);

    uint8_t len_bytes[8];
    for (i = 0; i < 8; ++i) {
        len_bytes[i] = (uint8_t)(total_bits >> ((7 - i) * 8));
    }
    lk_sha256_update(ctx, len_bytes, 8);

    for (i = 0; i < 8; ++i) {
        hash[i * 4]     = (uint8_t)(ctx->state[i] >> 24);
        hash[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        hash[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        hash[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

static inline void lk_sha256(const uint8_t *data, size_t len, uint8_t hash[32]) {
    lk_sha256_ctx ctx;
    lk_sha256_init(&ctx);
    lk_sha256_update(&ctx, data, len);
    lk_sha256_final(&ctx, hash);
}

/* HMAC-SHA256 */
static inline void lk_hmac_sha256(const uint8_t *key, size_t key_len,
                                  const uint8_t *data, size_t data_len,
                                  uint8_t out[32]) {
    uint8_t k[64];
    uint8_t k_ipad[64], k_opad[64];
    uint8_t ihash[32];
    size_t i;

    memset(k, 0, sizeof(k));
    if (key_len > 64) {
        lk_sha256(key, key_len, k);
    } else {
        memcpy(k, key, key_len);
    }

    for (i = 0; i < 64; ++i) {
        k_ipad[i] = k[i] ^ 0x36;
        k_opad[i] = k[i] ^ 0x5c;
    }

    lk_sha256_ctx ctx;
    lk_sha256_init(&ctx);
    lk_sha256_update(&ctx, k_ipad, 64);
    lk_sha256_update(&ctx, data, data_len);
    lk_sha256_final(&ctx, ihash);

    lk_sha256_init(&ctx);
    lk_sha256_update(&ctx, k_opad, 64);
    lk_sha256_update(&ctx, ihash, 32);
    lk_sha256_final(&ctx, out);
}

/* ChaCha20 Implementation (RFC 8439) */
#define LK_ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))
#define LK_QR(a, b, c, d) \
    a += b; d ^= a; d = LK_ROTL32(d, 16); \
    c += d; b ^= c; b = LK_ROTL32(b, 12); \
    a += b; d ^= a; d = LK_ROTL32(d, 8);  \
    c += d; b ^= c; b = LK_ROTL32(b, 7);

typedef struct {
    uint32_t state[16];
    uint8_t  keystream[64];
    size_t   available;
} lk_chacha20_ctx;

static inline uint32_t lk_load32_le(const uint8_t *p) {
    return ((uint32_t)p[0]) |
           (((uint32_t)p[1]) << 8) |
           (((uint32_t)p[2]) << 16) |
           (((uint32_t)p[3]) << 24);
}

static inline void lk_store32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static inline void lk_chacha20_init(lk_chacha20_ctx *ctx,
                                    const uint8_t key[32],
                                    const uint8_t nonce[12],
                                    uint32_t counter) {
    /* Constants "expand 32-byte k" */
    ctx->state[0] = 0x61707865;
    ctx->state[1] = 0x3320646e;
    ctx->state[2] = 0x79622d32;
    ctx->state[3] = 0x6b206574;

    /* 256-bit Key */
    ctx->state[4]  = lk_load32_le(key + 0);
    ctx->state[5]  = lk_load32_le(key + 4);
    ctx->state[6]  = lk_load32_le(key + 8);
    ctx->state[7]  = lk_load32_le(key + 12);
    ctx->state[8]  = lk_load32_le(key + 16);
    ctx->state[9]  = lk_load32_le(key + 20);
    ctx->state[10] = lk_load32_le(key + 24);
    ctx->state[11] = lk_load32_le(key + 28);

    /* 32-bit Counter */
    ctx->state[12] = counter;

    /* 96-bit Nonce */
    ctx->state[13] = lk_load32_le(nonce + 0);
    ctx->state[14] = lk_load32_le(nonce + 4);
    ctx->state[15] = lk_load32_le(nonce + 8);

    ctx->available = 0;
}

static inline void lk_chacha20_block(lk_chacha20_ctx *ctx) {
    uint32_t x[16];
    int i;
    for (i = 0; i < 16; ++i) x[i] = ctx->state[i];

    for (i = 0; i < 10; ++i) {
        /* Column round */
        LK_QR(x[0], x[4],  x[8], x[12]);
        LK_QR(x[1], x[5],  x[9], x[13]);
        LK_QR(x[2], x[6], x[10], x[14]);
        LK_QR(x[3], x[7], x[11], x[15]);

        /* Diagonal round */
        LK_QR(x[0], x[5], x[10], x[15]);
        LK_QR(x[1], x[6], x[11], x[12]);
        LK_QR(x[2], x[7],  x[8], x[13]);
        LK_QR(x[3], x[4],  x[9], x[14]);
    }

    for (i = 0; i < 16; ++i) {
        lk_store32_le(ctx->keystream + (i * 4), x[i] + ctx->state[i]);
    }

    ctx->state[12]++;
    ctx->available = 64;
}

static inline void lk_chacha20_xor(lk_chacha20_ctx *ctx,
                                   const uint8_t *in,
                                   uint8_t *out,
                                   size_t len) {
    size_t i = 0;

    /* Consume existing buffered keystream */
    if (ctx->available > 0) {
        size_t offset = 64 - ctx->available;
        size_t chunk = (len < ctx->available) ? len : ctx->available;
        for (size_t j = 0; j < chunk; ++j) {
            out[i + j] = in[i + j] ^ ctx->keystream[offset + j];
        }
        ctx->available -= chunk;
        i += chunk;
    }

    /* Process full 64-byte blocks directly */
    while (i + 64 <= len) {
        lk_chacha20_block(ctx);
        for (size_t j = 0; j < 64; ++j) {
            out[i + j] = in[i + j] ^ ctx->keystream[j];
        }
        ctx->available = 0;
        i += 64;
    }

    /* Process remaining bytes */
    if (i < len) {
        lk_chacha20_block(ctx);
        size_t rem = len - i;
        for (size_t j = 0; j < rem; ++j) {
            out[i + j] = in[i + j] ^ ctx->keystream[j];
        }
        ctx->available = 64 - rem;
    }
}

/* Stateless Per-Packet ChaCha20 Cryptor for UDP Datagrams */
static inline void lk_chacha20_crypt_packet(const uint8_t key[32],
                                            const uint8_t nonce[12],
                                            uint32_t counter,
                                            const uint8_t *in,
                                            uint8_t *out,
                                            size_t len) {
    lk_chacha20_ctx ctx;
    lk_chacha20_init(&ctx, key, nonce, counter);
    lk_chacha20_xor(&ctx, in, out, len);
}

/* Cryptographically Secure Random Bytes */
static inline int lk_random_bytes(uint8_t *buf, size_t len) {
#ifdef _WIN32
    HCRYPTPROV prov;
    if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return -1;
    }
    BOOL ok = CryptGenRandom(prov, (DWORD)len, buf);
    CryptReleaseContext(prov, 0);
    return ok ? 0 : -1;
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t total = 0;
    while (total < len) {
        ssize_t n = read(fd, buf + total, len - total);
        if (n <= 0) {
            close(fd);
            return -1;
        }
        total += (size_t)n;
    }
    close(fd);
    return 0;
#endif
}

#endif /* LIVEKADEH_CRYPTO_H */
