#include "config.h"
#include "raw_socket.h"

void encryptDecrypt(char outString[], const char inpString[], char xorKey[]) {
    // calculate length of input string
    int lenS = strlen(inpString);
    int lenK = strlen(xorKey);

    // perform XOR operation of key
    // with every character in string
    for (int i = 0; i < lenS; i++)
        outString[i] = inpString[i] ^ xorKey[i%lenK];
}
