#ifndef FILEENCRYPTION_H
#define FILEENCRYPTION_H

#include <iostream>
#include <fstream>
#include <string>

using namespace std;

#include "cbc.h"

class FileEncryption
{
public:
    FileEncryption(uint64_t key);
    int encrypt(string input, string output);
    int decrypt(string input, string output);
    int cipher (string input, string output, bool mode);

private:
    CBC des;
};

#endif 