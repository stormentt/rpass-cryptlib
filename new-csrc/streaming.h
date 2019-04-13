#ifndef RPASS_STREAMING_H
#define RPASS_STREAMING_H

#include "rpass-cryptlib.h"

void stream_keygen(BYTES buf);

void stream_init_encrypt(STREAM_STATE *state, STREAM_HEADER header, STREAM_KEY k);
enum RC stream_encrypt(STREAM_STATE *state, BYTES c, BYTES m, BYTES_LEN mlen, int end);

enum RC stream_init_decrypt(STREAM_STATE *state, STREAM_HEADER header, STREAM_KEY key);
enum RC stream_decrypt(STREAM_STATE *state, BYTES m, BYTES c, BYTES_LEN clen, int *end);

#endif
