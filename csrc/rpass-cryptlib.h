#ifndef RPASS_CRYPTLIB_H
#define RPASS_CRYPTLIB_H

#define _GNU_SOURCE
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define CHUNK_SIZE 16384

enum RC {
    SUCCESS,
    SODIUM_INIT_ERROR,

    DECRYPTION_ERROR,
    ENCRYPTION_ERROR,

    INPUT_HEADER_INVALID,
    INPUT_HEADER_READ_ERROR,
    INPUT_OPEN_ERROR,
    INPUT_PREMATURE_EOF,
    INPUT_READ_ERROR,

    OUTPUT_CLOSE_ERROR,
    OUTPUT_OPEN_ERROR,
    OUTPUT_WRITE_ERROR
};

const size_t ENCRYPT_OVERHEAD = crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES;
const size_t ENCRYPT_KEYSIZE = crypto_secretbox_KEYBYTES;
const size_t FILE_ENCRYPT_KEYSIZE = crypto_secretstream_xchacha20poly1305_KEYBYTES;

const char* rc2str(enum RC rc);
int init();

size_t encrypt_overhead();
size_t encrypt_keysize();
size_t file_encrypt_keysize();

enum RC random_bytes(unsigned char *buf, size_t len);
enum RC random_alphanum(unsigned char *buf, size_t len);

enum RC encrypt(unsigned char *out, unsigned char *in, size_t in_len, const unsigned char key[ENCRYPT_KEYSIZE]);
enum RC decrypt(unsigned char *out, unsigned char *in, size_t in_len, const unsigned char key[ENCRYPT_KEYSIZE]);

enum RC encrypt_file(const char *out_path, const char *in_path, const unsigned char key[FILE_ENCRYPT_KEYSIZE]);
enum RC decrypt_file(const char *out_path, const char *in_path, const unsigned char key[FILE_ENCRYPT_KEYSIZE]);
#endif
