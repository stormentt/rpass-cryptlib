#include <stdio.h>
#include "rpass-cryptlib.h"

int main() { 
    init();

    STREAM_KEY k = { 0 };
    stream_keygen(k);

    FILE *keyfile = fopen("keyfile", "w+");
    if (keyfile == NULL) {
        perror("unable to open keyfile");
        return 1;
    }

    fwrite(k, 32, 1, keyfile);
    if (fclose(keyfile) != 0) {
        perror(" unable to close keyfile");
        return 1;
    }
}
