#ifndef RPASS_DEFS_H
#define RPASS_DEFS_H
#include <sodium.h>

//
// Global
//
typedef unsigned char* BYTES;
typedef unsigned long long BYTES_LEN;

//
// Simple Encryption
//
#define ENCRYPTION_ABYTES   (crypto_secretbox_MACBYTES + crypto_secretbox_NONCEBYTES)
#define ENCRYPTION_KEY_LEN   crypto_secretbox_KEYBYTES
#define ENCRYPTION_NONCE_LEN crypto_secretbox_NONCEBYTES

#define ENCRYPTION_KEYGEN(buf)          crypto_secretbox_keygen(buf)
#define ENCRYPT(c, m, mlen, nonce, key) crypto_secretbox_easy(c, m, mlen, nonce, key)
#define DECRYPT(m, c, clen, nonce, key) crypto_secretbox_open_easy(m, c, clen, nonce, key)

typedef unsigned char ENCRYPTION_KEY[ENCRYPTION_KEY_LEN];
typedef unsigned char ENCRYPTION_NONCE[ENCRYPTION_NONCE_LEN];

extern const size_t encryption_abytes;
extern const size_t encryption_key_len;
extern const size_t encryption_nonce_len;

// 
// Stream Encryption
//
#define STREAM_ABYTES     crypto_secretstream_xchacha20poly1305_ABYTES
#define STREAM_MAX_MLEN   crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX
#define STREAM_TAG_FINAL  crypto_secretstream_xchacha20poly1305_TAG_FINAL
#define STREAM_HEADER_LEN crypto_secretstream_xchacha20poly1305_HEADERBYTES
#define STREAM_KEY_LEN    crypto_secretstream_xchacha20poly1305_KEYBYTES

#define STREAM_KEYGEN(buf)            crypto_secretstream_xchacha20poly1305_keygen(buf)
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
extern const size_t stream_abytes;

// 
// Hashing
//
#define HASH_KEY_LEN      crypto_generichash_KEYBYTES
#define HASH_LEN          crypto_generichash_BYTES
#define HASH_KEYGEN(buf)  crypto_generichash_keygen(buf)
#define HASH_STATE        crypto_generichash_state

typedef unsigned char HASH_KEY[HASH_KEY_LEN];
extern const size_t hash_key_len;
extern const size_t hash_len;

#define HASH(out, m, mlen, key) crypto_generichash(out, HASH_LEN, m, mlen, key, HASH_KEY_LEN)
#define HASH_INIT(state, key)       crypto_generichash_init(state, key, HASH_KEY_LEN, HASH_LEN)
#define HASH_UPDATE(state, m, mlen) crypto_generichash_update(state, m, mlen)
#define HASH_FINAL(state, out)      crypto_generichash_final(state, out, HASH_LEN)

#define HASH_COMPARE(m1, m2) sodium_memcmp(m1, m2, HASH_LEN)

#endif
