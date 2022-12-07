#ifndef CBC_H
#define CBC_H

#include "des.h"

class CBC {
public:
    CBC(uint64_t key, uint64_t iv);
    uint64_t encrypt(uint64_t block);
    uint64_t decrypt(uint64_t block);
    void reset();

private:
    DES des;
    uint64_t iv;
    uint64_t last_block;
};

#endif