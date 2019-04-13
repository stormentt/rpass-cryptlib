#ifndef RPASS_HASHING_H
#define RPASS_HASHING_H
#include "rpass-cryptlib.h"

void hash_keygen(BYTES buf);
void hash(BYTES out, BYTES m, BYTES_LEN mlen, HASH_KEY key);

void hash_init(HASH_STATE *state, HASH_KEY key);
void hash_update(HASH_STATE *state, BYTES m, BYTES_LEN mlen);
void hash_final(HASH_STATE *state, BYTES out);

enum RC hash_equals(BYTES m1, BYTES m2);

#endif
