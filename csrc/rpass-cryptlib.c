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

        case INPUT_HEADER_INVALID:
            return "input header is corrupted";
        case INPUT_HEADER_READ_ERROR:
            return "error reading input header";
        case INPUT_OPEN_ERROR:
            return "error opening input file";
        case INPUT_PREMATURE_EOF:
            return "input file prematurely ended, more data was expected";
        case INPUT_READ_ERROR:
            return "error reading input file";

        case OUTPUT_CLOSE_ERROR:
            return "error closing/flushing output file";
        case OUTPUT_OPEN_ERROR:
            return "error opening output file";
        case OUTPUT_WRITE_ERROR:
            return "error writing output file";
        default:
            return "invalid error code";
    }
}

int init() {
    return sodium_init();
}

size_t encrypt_overhead() {
    return ENCRYPT_OVERHEAD;
}
size_t encrypt_keysize() {
    return ENCRYPT_KEYSIZE;
}
size_t file_encrypt_keysize() {
    return FILE_ENCRYPT_KEYSIZE;
}

enum RC random_bytes(unsigned char *buf, size_t len) {
    if (init() < 0) {
        return SODIUM_INIT_ERROR;
    }

    randombytes_buf(buf, len);

    return SUCCESS;
}

enum RC random_alphanum(unsigned char *buf, size_t len) {
    if (init() < 0) {
        return SODIUM_INIT_ERROR;
    }

    randombytes_buf(buf, len);

    unsigned char *u = buf;
    for (size_t i = 0; i < len; i++) {
        u = buf + i;

        *u &= 0x3f; // 0011 1111
        // This drops off the 2 most significant bits, leaving us with 6 bits
        // We now have 6 random bits.

        // 6 bits gives us 64 possibilities, 0-63. 
        // We want to generate alphanumeric passwords, so we have 62 (0-9,a-z,A-Z) characters.
        // 6 bits = 64 possiblities, since 64 is greater than 62 we have to "reroll" on two of our possiblities.
        // 63 - 2 = 61.
        while (*u > 61) {
            // Regenerate this and clamp it to 6 bits.
            randombytes_buf(u,1);
            *u &= 0x3f;
        };

        // this block of code converts a number from 0-61 inclusive to mixed case alphanumeric ASCII
        // 0-9 -> 0-9
        // 10-35 -> A-Z
        // 36-61 -> a-z

        if (*u < 10) {
            // 0,1,2,3...9 occupy 48 - 57 of the ASCII table
            *u += 48;
        } else if (*u < 36) {
            // A-Z occupy 65-90 of the ASCII table
            // 65 - 10 = 55
            *u += 55;
        } else {
            // a-z occupy 97-122 of the ASCII table
            // 97 - 36 = 61
            *u += 61;
        }
    }

    return SUCCESS;
}

enum RC encrypt(unsigned char *out, unsigned char *in, size_t in_len, const unsigned char key[ENCRYPT_KEYSIZE]) {
    if (init() < 0) {
        return SODIUM_INIT_ERROR;
    }

    unsigned char nonce[crypto_secretbox_NONCEBYTES] = { 0 };
    randombytes_buf(nonce, sizeof nonce);
    memcpy(out, nonce, crypto_secretbox_NONCEBYTES);

    if (crypto_secretbox_easy(out+crypto_secretbox_NONCEBYTES, in, in_len, nonce, key) != 0) {
        return ENCRYPTION_ERROR;
    }

    return SUCCESS;
}

enum RC decrypt(unsigned char *out, unsigned char *in, size_t in_len, const unsigned char key[ENCRYPT_KEYSIZE]) {
    if (init() < 0) {
        return SODIUM_INIT_ERROR;
    }

    unsigned char nonce[crypto_secretbox_NONCEBYTES] = { 0 };
    memcpy(nonce, in, crypto_secretbox_NONCEBYTES);

    if (crypto_secretbox_open_easy(out, in + crypto_secretbox_NONCEBYTES, in_len - crypto_secretbox_NONCEBYTES, nonce, key) != 0) {
        return DECRYPTION_ERROR;
    }

    return SUCCESS;
}

enum RC encrypt_file(const char *out_path, const char *in_path, const unsigned char key[FILE_ENCRYPT_KEYSIZE]) {
    if (init() < 0) {
        return SODIUM_INIT_ERROR;
    }
    unsigned char buf_in[CHUNK_SIZE] = { 0 };
    unsigned char buf_out[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES] = { 0 };
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES] = { 0 };
    crypto_secretstream_xchacha20poly1305_state st;
    FILE *out, *in;
    unsigned long long out_len;
    size_t rlen, wlen;
    int eof;
    unsigned char tag;

    enum RC ret = ENCRYPTION_ERROR;

    in = fopen(in_path, "rb");
    if (in == NULL) {
        ret = INPUT_OPEN_ERROR;
        return ret;
    }

    out = fopen(out_path, "wb");
    if (out == NULL) {
        ret = OUTPUT_OPEN_ERROR;
        goto ret;
    }

    crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);
    fwrite(header, 1, sizeof header, out);
    do {
        rlen = fread(buf_in, 1, sizeof buf_in, in);
        eof = feof(in);
        if (rlen < sizeof buf_in && !eof) {
            ret = INPUT_READ_ERROR;
            goto ret;
        }

        tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
        if (crypto_secretstream_xchacha20poly1305_push(&st, buf_out, &out_len, buf_in, rlen, NULL, 0, tag) != 0) {
            ret = ENCRYPTION_ERROR;
            goto ret;
        }

        wlen = fwrite(buf_out, 1, (size_t) out_len, out);
        if (wlen != out_len) {
            ret = OUTPUT_WRITE_ERROR;
            goto ret;
        }
    } while (! eof);

    ret = SUCCESS;
ret:
    fclose(in);
    if (ret == SUCCESS && fclose(out) != 0) {
        ret = OUTPUT_CLOSE_ERROR;
    }

    return ret;
}


enum RC decrypt_file(const char *out_path, const char *in_path, const unsigned char key[FILE_ENCRYPT_KEYSIZE]) {
    if (init() < 0) {
        return SODIUM_INIT_ERROR;
    }

    unsigned char buf_in[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES] = { 0 };
    unsigned char buf_out[CHUNK_SIZE] = { 0 };
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES] = { 0 };
    crypto_secretstream_xchacha20poly1305_state st;
    FILE *out, *in;
    unsigned long long out_len;
    size_t rlen, wlen;
    int eof;
    enum RC ret = DECRYPTION_ERROR;
    unsigned char tag;


    in = fopen(in_path, "rb");
    if (in == NULL) {
        ret = INPUT_OPEN_ERROR;
        return ret;
    }

    out = fopen(out_path, "wb");
    if (out == NULL) {
        ret = OUTPUT_OPEN_ERROR;
        goto ret;
    }

    rlen = fread(header, 1, sizeof header, in);
    if (rlen != sizeof header) {
        ret = INPUT_HEADER_READ_ERROR;
        goto ret;
    }

    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
        ret = INPUT_HEADER_INVALID;
        goto ret;
    }

    do {
        rlen = fread(buf_in, 1, sizeof buf_in, in);
        eof = feof(in);
        if (rlen < sizeof buf_in && !eof) {
            ret = INPUT_READ_ERROR;
            goto ret;
        }

        if (crypto_secretstream_xchacha20poly1305_pull(&st, buf_out, &out_len, &tag,
                    buf_in, rlen, NULL, 0) != 0) {
            ret = DECRYPTION_ERROR;
            goto ret;
        }

        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL && ! eof) {
            ret = INPUT_PREMATURE_EOF;
            goto ret;
        }

        wlen = fwrite(buf_out, 1, (size_t) out_len, out);
        if (wlen != out_len) {
            ret = OUTPUT_WRITE_ERROR;
            goto ret;
        }
    } while (! eof);

    ret = SUCCESS;
ret:
    fclose(in);
    if (ret == SUCCESS && fclose(out) != 0) {
        return OUTPUT_CLOSE_ERROR;
    }
    return ret;
}
