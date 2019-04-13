#ifndef RPASS_ENCRYPTION_H
#define RPASS_ENCRYPTION_H
#include "rpass-cryptlib.h"

void encryption_keygen(BYTES buf);
void encryption_noncegen(BYTES buf);

void encrypt(BYTES c, BYTES m, BYTES_LEN mlen, ENCRYPTION_KEY key);
enum RC decrypt(BYTES m, BYTES c, BYTES_LEN clen, ENCRYPTION_KEY key);
#endif
