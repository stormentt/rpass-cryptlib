#ifndef RPASS_ERRORS_H
#define RPASS_ERRORS_H
enum RC {
    SUCCESS,
    SODIUM_INIT_ERROR,

    DECRYPTION_ERROR,
    ENCRYPTION_ERROR,
    HASHING_ERROR,

    HEADER_INVALID,

    MESSAGE_TOO_LONG,
};

const char* rc2str(enum RC rc);
#endif