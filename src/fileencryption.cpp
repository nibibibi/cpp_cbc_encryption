#include "fileencryption.h"

FileEncryption::FileEncryption(uint64_t key) : des(key, (uint64_t) 0x0000000000000000) {}

int FileEncryption::encrypt(string input, string output) {
    return cipher(input, output, false);
}

int FileEncryption::decrypt(string input, string output) {
    return cipher(input, output, true);
}

int FileEncryption::cipher(string input, string output, bool mode) {
    ifstream ifile;
    ofstream ofile;
    uint64_t buffer;

    if(input.length()  < 1) input  = "/dev/stdin";
    if(output.length() < 1) output = "/dev/stdout";

    ifile.open(input,  ios::binary | ios::in | ios::ate);
    ofile.open(output, ios::binary | ios::out);

    uint64_t size = ifile.tellg();
    ifile.seekg(0, ios::beg);

    uint64_t block = size / 8;
    if(mode) block--;

    for(uint64_t i = 0; i < block; i++) {
        ifile.read((char*) &buffer, 8);

        if(mode)
            buffer = des.decrypt(buffer);
        else
            buffer = des.encrypt(buffer);

        ofile.write((char*) &buffer, 8);
    }

    if(mode == false) {
        uint8_t padding = 8 - (size % 8);

        if (padding == 0)
            padding  = 8;

        buffer = (uint64_t) 0;
        if(padding != 8)
            ifile.read((char*) &buffer, 8 - padding);

        uint8_t shift = padding * 8;
        buffer <<= shift;
        buffer  |= (uint64_t) 0x0000000000000001 << (shift - 1);

        buffer = des.encrypt(buffer);
        ofile.write((char*) &buffer, 8);
    } else {
        ifile.read((char*) &buffer, 8);
        buffer = des.decrypt(buffer);

        uint8_t padding = 0;
        uint64_t counter = 0; /////
        while(!(buffer & 0x00000000000000ff))
        {
            cout << "while" << counter << endl;
            buffer >>= 8;
            padding++;
        }

        buffer >>= 8;
        padding++;

        if(padding != 8)
            ofile.write((char*) &buffer, 8 - padding);
    }

    ifile.close();
    ofile.close();
    return 0;
}