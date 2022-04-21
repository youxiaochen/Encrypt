//
// Created by you on 2019/5/17.
//
#include <cstdlib>

#ifndef ENCRYPT_ENCRY_UTILS_H
#define ENCRYPT_ENCRY_UTILS_H

//16进制字符串转buffer
bool hex2Buffer(const char *str, size_t len, unsigned char *buffer);

//buffer转16进制字符串, str长度应当+1用于结束符
bool buffer2Hex(const unsigned char *buffer, size_t len, char *str);

#endif //ENCRYPT_ENCRY_UTILS_H
