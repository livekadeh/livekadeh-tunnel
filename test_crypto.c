#include <stdio.h>
#include <assert.h>
#include "crypto.h"

int main(void) {
    /* Test SHA-256 with "abc" */
    uint8_t hash[32];
    lk_sha256((const uint8_t *)"abc", 3, hash);
    /* ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad */
    assert(hash[0] == 0xba && hash[1] == 0x78 && hash[2] == 0x16 && hash[3] == 0xbf);
    printf("SHA-256 test passed.\n");

    /* Test ChaCha20 reversible XOR */
    uint8_t key[32] = {1, 2, 3, 4, 5};
    uint8_t nonce[12] = {9, 8, 7};
    lk_chacha20_ctx ctx_enc, ctx_dec;
    lk_chacha20_init(&ctx_enc, key, nonce, 1);
    lk_chacha20_init(&ctx_dec, key, nonce, 1);

    const char *secret_msg = "Hello Livekadeh Tunnel 2026!";
    size_t msg_len = strlen(secret_msg);
    uint8_t encrypted[64];
    uint8_t decrypted[64];

    lk_chacha20_xor(&ctx_enc, (const uint8_t *)secret_msg, encrypted, msg_len);
    assert(memcmp(secret_msg, encrypted, msg_len) != 0);

    lk_chacha20_xor(&ctx_dec, encrypted, decrypted, msg_len);
    decrypted[msg_len] = '\0';
    assert(strcmp(secret_msg, (char *)decrypted) == 0);
    printf("ChaCha20 test passed: %s\n", decrypted);

    /* Test random bytes */
    uint8_t rand_buf[16];
    assert(lk_random_bytes(rand_buf, 16) == 0);
    printf("Random bytes test passed.\n");

    return 0;
}

