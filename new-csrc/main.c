#include <stdio.h>
#include <stdlib.h>
#include "rpass-cryptlib.h"

int encrypt_example();
int file_example();

int main() { 
    init();

    if (encrypt_example() != 0) {
        puts("encrypt example failed");
        return 1;
    }

    if (file_example() != 0) {
        puts("file example failed");
        return 1;
    }
}

int encrypt_example() {
    puts("encrypt_example(): ");
    BYTES m = "hello world!";
    BYTES_LEN m_len = 13;

    BYTES_LEN c_len = m_len + ENCRYPTION_ABYTES;
    BYTES c = calloc(c_len, 1);

    BYTES_LEN d_len = c_len - ENCRYPTION_ABYTES;
    BYTES d = calloc(d_len, 1);

    ENCRYPTION_KEY key = { 0 };

    encryption_keygen(key);

    encrypt(c, m, m_len, key);

    if (decrypt(d, c, c_len, key) != SUCCESS) {
        puts("decryption failed");
        return 1;
    }

    puts(d);
    return sodium_memcmp(m, d, m_len);
}

int file_example() {
    puts("file_example(): ");

    STREAM_STATE state;
    STREAM_HEADER header;
    STREAM_KEY key = { 0 };
    stream_keygen(key);

    // messages
    BYTES m1 = "hello world!\n";
    BYTES_LEN m1_len = 13;

    BYTES m2 = "this is ";
    BYTES_LEN m2_len = 8;

    BYTES m3 = "a test!";
    BYTES_LEN m3_len = 8; // \0

    // ciphertexts
    BYTES_LEN c1_len = m1_len + STREAM_ABYTES, 
              c2_len = m2_len + STREAM_ABYTES, 
              c3_len = m3_len + STREAM_ABYTES;
    BYTES c1 = calloc(c1_len, 1), 
          c2 = calloc(c2_len, 1), 
          c3 = calloc(c3_len, 1);

    // decrypted ciphertexts
    BYTES d1 = calloc(m1_len, 1), 
          d2 = calloc(m2_len, 1), 
          d3 = calloc(m3_len, 1);

    BYTES_LEN d1_len = c1_len - STREAM_ABYTES, 
              d2_len = c2_len - STREAM_ABYTES, 
              d3_len = c3_len - STREAM_ABYTES;

    stream_init_encrypt(&state, header, key);

    if (stream_encrypt(&state, c1, m1, m1_len, 0) != SUCCESS)  {
        puts("unable to encrypt m1");
        return 1;
    }
    if (stream_encrypt(&state, c2, m2, m2_len, 0) != SUCCESS)  {
        puts("unable to encrypt m2");
        return 1;
    }
    if (stream_encrypt(&state, c3, m3, m3_len, 1) != SUCCESS)  {
        puts("unable to encrypt m3");
        return 1;
    }


    STREAM_STATE d_state;
    if (stream_init_decrypt(&d_state, header, key) != SUCCESS) {
        puts("bad decrypt header");
        return 1;
    }

    int end = 0;

    // c1 -> d1
    if (stream_decrypt(&d_state, d1, c1, c1_len, &end) != SUCCESS) {
        puts("unable to decrypt c1");
        return 1;
    }
    if (end == 1) {
        puts("c1 had final tag");
        return 1;
    }

    // c2 -> d2
    if (stream_decrypt(&d_state, d2, c2, c2_len, &end) != SUCCESS) {
        puts("unable to decrypt c2");
        return 1;
    }
    if (end == 1) {
        puts("c2 had final tag");
        return 1;
    }

    // c3 -> d3
    if (stream_decrypt(&d_state, d3, c3, c3_len, &end) != SUCCESS) {
        puts("unable to decrypt c3");
        return 1;
    }
    if (end != 1) {
        puts("c3 did not have final tag");
        return 1;
    }

    puts(d1);
    puts(d2);
    puts(d3);

    return 0;
}
