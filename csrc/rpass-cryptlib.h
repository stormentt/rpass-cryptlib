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


const char* rc2str(enum RC rc);
int init();
unsigned char* random_bytes(int);
unsigned char* encrypt(unsigned char*, unsigned long long, unsigned long long*, const unsigned char key[crypto_secretbox_KEYBYTES]);
unsigned char* decrypt(unsigned char*, unsigned long long, unsigned long long*, const unsigned char key[crypto_secretbox_KEYBYTES]);
enum RC encrypt_file(const char*, const char*, const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]);
enum RC decrypt_file(const char*, const char*, const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]);
#endif
