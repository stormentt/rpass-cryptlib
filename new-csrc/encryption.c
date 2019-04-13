#include "encryption.h"

void encryption_keygen(BYTES buf) {
    ENCRYPTION_KEYGEN(buf);
}

void encryption_noncegen(BYTES buf) {
    randombytes_buf(buf, ENCRYPTION_NONCE_LEN);
}

void encrypt(BYTES c, BYTES m, BYTES_LEN mlen, ENCRYPTION_KEY key) {
    BYTES nonce = c;
    encryption_noncegen(nonce);

    ENCRYPT(c + ENCRYPTION_NONCE_LEN, m, mlen, nonce, key);
}

enum RC decrypt(BYTES m, BYTES c, BYTES_LEN clen, ENCRYPTION_KEY key) {
    BYTES nonce = c;

    if (DECRYPT(m, c + ENCRYPTION_NONCE_LEN, clen - ENCRYPTION_NONCE_LEN, nonce, key) != 0) {
        return DECRYPTION_ERROR;
    }

    return SUCCESS;
}
