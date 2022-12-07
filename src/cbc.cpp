#include "cbc.h"

CBC::CBC(uint64_t key, uint64_t iv) : des(key), iv(iv), last_block(iv) {}

uint64_t CBC::encrypt(uint64_t block) {
    last_block = des.encrypt(block ^ last_block);
    return last_block;
}

uint64_t CBC::decrypt(uint64_t block) {
    uint64_t result = des.decrypt(block) ^ last_block;
    last_block = block;
    return result;
}

void CBC::reset() {
    last_block = iv;
}
