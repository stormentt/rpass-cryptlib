#include "rpass-cryptlib.h"

const char* rc2str(enum RC rc) {
    switch (rc) {
        case SUCCESS:
            return "success";
        case SODIUM_INIT_ERROR:
            return "error initializing libsodium";

        case DECRYPTION_ERROR:
            return "error decrypting input: maybe a bad key or input is corrupted";
        case ENCRYPTION_ERROR:
            return "error encrypting input: something has gone horribly wrong: good luck";
        case HASHING_ERROR:
            return "error hashing input: something has gone horribly wrong: good luck";

        case HEADER_INVALID:
            return "header is invalid; probably corrupted or wrong key";

        case MESSAGE_TOO_LONG:
            return "provided message is too long to encrypt";
        default:
            return "invalid error code; this shouldn't happen";
    }
}
