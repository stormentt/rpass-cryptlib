#include "streaming.h"

void stream_keygen(BYTES buf) {
    crypto_secretstream_xchacha20poly1305_keygen(buf);
}

void stream_init_encrypt(STREAM_STATE *state, STREAM_HEADER header, STREAM_KEY key) {
    crypto_secretstream_xchacha20poly1305_init_push(state, header, key);
}

enum RC stream_encrypt(STREAM_STATE *state, BYTES c, BYTES_LEN *clen, BYTES m, BYTES_LEN mlen, int end) {
    unsigned char tag = 0;
    if (end == 1) {
        tag = TAG_FINAL;
    }

    if (mlen > MAX_MLEN) {
        return MESSAGE_TOO_LONG;
    }

    if (PUSH(state, c, clen, m, mlen, tag) != 0) {
        return ENCRYPTION_ERROR;
    }

    return SUCCESS;
}

enum RC stream_init_decrypt(STREAM_STATE *state, STREAM_HEADER header, STREAM_KEY key) {
    if (INIT_PULL(state, header, key) != 0) {
        return HEADER_INVALID;
    }

    return SUCCESS;
}

enum RC stream_decrypt(STREAM_STATE *state, BYTES m, BYTES_LEN *mlen, BYTES c, BYTES_LEN clen, int *end) {
    unsigned char tag = 0;

    if (PULL(state, m, mlen, c, clen, &tag) != 0) {
        return DECRYPTION_ERROR;
    }

    if (tag == TAG_FINAL) {
        *end = 1;
    }

    return SUCCESS;
}
