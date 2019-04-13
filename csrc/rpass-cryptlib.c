#include "rpass-cryptlib.h"

int init() {
    if (sodium_init() < 0) {
        return SODIUM_INIT_ERROR;
    }

    return SUCCESS;
}
