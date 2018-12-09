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

unsigned char* random_bytes(int len) {
    unsigned char* rand = calloc(len, 1);
    randombytes_buf(rand, len);
    return rand;
}

unsigned char* encrypt(unsigned char* in, unsigned long long in_len, unsigned long long *out_len, const unsigned char key[crypto_secretbox_KEYBYTES]) {
    if (init() < 0) {
        return NULL;
    }

    *out_len = crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + in_len;
    unsigned char* out = calloc(*out_len, 1);

    unsigned char nonce[crypto_secretbox_NONCEBYTES] = { 0 };
    randombytes_buf(nonce, sizeof nonce);
    memcpy(out, nonce, crypto_secretbox_NONCEBYTES);

    if (crypto_secretbox_easy(out+crypto_secretbox_NONCEBYTES, in, in_len, nonce, key) != 0) {
        free(out);
        return NULL;
    }

    return out;
}

unsigned char* decrypt(unsigned char* in, unsigned long long in_len, unsigned long long *out_len, const unsigned char key[crypto_secretbox_KEYBYTES]) {
    if (init() < 0) {
        return NULL;
    }

    *out_len = in_len - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES;
    unsigned char* out = calloc(*out_len, 1);

    unsigned char nonce[crypto_secretbox_NONCEBYTES] = { 0 };
    memcpy(nonce, in, crypto_secretbox_NONCEBYTES);

    if (crypto_secretbox_open_easy(out, in + crypto_secretbox_NONCEBYTES, in_len - crypto_secretbox_NONCEBYTES, nonce, key) != 0) {
        free(out);
        return NULL;
    }

    return out;
}

enum RC encrypt_file(const char* opath, const char* ipath, const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]) {
    if (init() < 0) {
        return SODIUM_INIT_ERROR;
    }
    printf("encrypt_file() opath: %s\n", opath);
    printf("encrypt_file() ipath: %s\n", ipath);
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

    in = fopen(ipath, "rb");
    if (in == NULL) {
        ret = INPUT_OPEN_ERROR;
        return ret;
    }

    out = fopen(opath, "wb");
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


enum RC decrypt_file(const char* opath, const char* ipath, const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]) {
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


    in = fopen(ipath, "rb");
    if (in == NULL) {
        ret = INPUT_OPEN_ERROR;
        return ret;
    }

    out = fopen(opath, "wb");
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
