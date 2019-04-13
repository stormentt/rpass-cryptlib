#ifndef RPASS_TYPES_H
#define RPASS_TYPES_H
#include <sodium.h>

//
// Global
//
typedef unsigned char* BYTES;
typedef unsigned long long BYTES_LEN;

// 
// Streams
//
#define STREAM_ABYTES     crypto_secretstream_xchacha20poly1305_ABYTES
#define STREAM_MAX_MLEN   crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX
#define STREAM_TAG_FINAL  crypto_secretstream_xchacha20poly1305_TAG_FINAL
#define STREAM_HEADER_LEN crypto_secretstream_xchacha20poly1305_HEADERBYTES
#define STREAM_KEY_LEN    crypto_secretstream_xchacha20poly1305_KEYBYTES

#define KEYGEN(buf)                   crypto_secretstream_xchacha20poly1305_keygen(buf)
#define INIT_PUSH(state, header, key) crypto_secretstream_xchacha20poly1305_init_push(state, header, key)
#define PUSH(state, c, m, mlen, tag)  crypto_secretstream_xchacha20poly1305_push(state, c, NULL, m, mlen, NULL, 0, tag)

// NOTICE: The arguments in PULL have been switched around.
// I wanted my PULL and PUSH functions to have the same arguments list, so both of them have tag at the end. The real pull() function puts tag_p as the 4th argument, not the last.
#define INIT_PULL(state, header, key) crypto_secretstream_xchacha20poly1305_init_pull(state, header, key)
#define PULL(state, m, c, clen, tag)  crypto_secretstream_xchacha20poly1305_pull(state, m, NULL, tag, c, clen, NULL, 0)

#define STREAM_STATE    crypto_secretstream_xchacha20poly1305_state
typedef unsigned char STREAM_HEADER[STREAM_HEADER_LEN];
typedef unsigned char STREAM_KEY[STREAM_KEY_LEN];

extern const size_t stream_header_len;
extern const size_t stream_key_len;

#endif
