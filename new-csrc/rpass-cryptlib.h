#ifndef RPASS_CRYPTLIB_H
#define RPASS_CRYPTLIB_H
#include <sodium.h>

#include "defs.h"
#include "errors.h"
#include "streaming.h"

#define ENCRYPT_OVERHEAD crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES
#define ENCRYPT_KEYSIZE crypto_secretbox_KEYBYTES
#define FILE_ENCRYPT_KEYSIZE crypto_secretstream_xchacha20poly1305_KEYBYTES


int init();

#endif
