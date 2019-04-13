#include "hashing.h"

void hash_keygen(BYTES buf) {
    HASH_KEYGEN(buf);
}

void hash(BYTES out, BYTES m, BYTES_LEN mlen, HASH_KEY key) {
    HASH(out, m, mlen, key);
}

void hash_init(HASH_STATE *state, HASH_KEY key) {
    HASH_INIT(state, key);
}

void hash_update(HASH_STATE *state, BYTES m, BYTES_LEN mlen) {
    HASH_UPDATE(state, m, mlen);
}

void hash_final(HASH_STATE *state, BYTES out) {
    HASH_FINAL(state, out);
}

enum RC hash_equals(BYTES m1, BYTES m2) {
    if (HASH_COMPARE(m1, m2) != 0) {
        return HASH_MISMATCH;
    }

    return SUCCESS;
}
