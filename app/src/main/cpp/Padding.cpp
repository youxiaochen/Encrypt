//
// Created by you on 2019/6/19.
//
#include "Pading.h"

void Padding::padding(std::string &src, int alignSize, PaddingModel mode) {
    int remainder = src.length() % alignSize;
    int paddingSize = (remainder == 0) ? alignSize : (alignSize - remainder);
    switch (mode) {
        case PKCS5OR7:
            src.append(paddingSize, paddingSize);
            break;
        case ZERO:
        default:
            src.append(paddingSize, 0);
            break;
    }
}

void Padding::unpadding(std::string &src) {
    int c = src[src.length() - 1];
    if (c > 0) src.erase(src.length() - c, c);
}
