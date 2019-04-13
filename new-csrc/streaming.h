#ifndef RPASS_STREAMING_H
#define RPASS_STREAMING_H

#include "rpass-cryptlib.h"

#define ABYTES crypto_secretstream_xchacha20poly1305_ABYTES
#define MAX_MLEN crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX
#define TAG_FINAL crypto_secretstream_xchacha20poly1305_TAG_FINAL
#define STREAM_HEADER_LEN crypto_secretstream_xchacha20poly1305_KEYBYTES
#define STREAM_KEY_LEN crypto_secretstream_xchacha20poly1305_KEYBYTES

#define KEYGEN(buf) crypto_secretstream_xchacha20poly1305_keygen(buf)
#define INIT_PUSH(state, header, key) crypto_secretstream_xchacha20poly1305_init_push(state, header, key)
#define PUSH(state, c, m, mlen, tag) crypto_secretstream_xchacha20poly1305_push(state, c, NULL, m, mlen, NULL, 0, tag)

//
// NOTICE: The arguments in PULL have been switched around.
// I wanted my PULL and PUSH functions to have the same arguments list, so both of them have tag at the end. The real pull() function puts tag_p as the 4th argument, not the last.
#define INIT_PULL(state, header, key) crypto_secretstream_xchacha20poly1305_init_pull(state, header, key)
#define PULL(state, m, c, clen, tag) crypto_secretstream_xchacha20poly1305_pull(state, m, NULL, tag, c, clen, NULL, 0)


typedef crypto_secretstream_xchacha20poly1305_state STREAM_STATE;
typedef unsigned char STREAM_KEY[STREAM_KEY_LEN];
typedef unsigned char STREAM_HEADER[STREAM_HEADER_LEN];

void stream_keygen(BYTES buf);

void stream_init_encrypt(STREAM_STATE *state, STREAM_HEADER header, STREAM_KEY k);
enum RC stream_encrypt(STREAM_STATE *state, BYTES c, BYTES m, BYTES_LEN mlen, int end);

enum RC stream_init_decrypt(STREAM_STATE *state, STREAM_HEADER header, STREAM_KEY key);
enum RC stream_decrypt(STREAM_STATE *state, BYTES m, BYTES c, BYTES_LEN clen, int *end);

#endif
