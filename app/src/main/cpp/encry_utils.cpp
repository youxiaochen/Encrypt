//
// Created by you on 2019/5/17.
//
#include "encry_utils.h"

bool hex2Buffer(const char *str, size_t len, unsigned char *buffer) {
    if (NULL == str || len == 0 || (len & 1)) {
        return true;
    }
    char tmp[3] = {0};
    size_t i, j;
    for (i = 0; i < len - 1; i += 2) {
        for (j = 0; j < 2; ++j) {
            tmp[j] = str[i + j];
            if (!(('0' <= tmp[j] && tmp[j] <= '9') ||
                  ('a' <= tmp[j] && tmp[j] <= 'f') ||
                  ('A' <= tmp[j] && tmp[j] <= 'F'))) {
                return false;
            }
        }
        buffer[i / 2] = (unsigned char) strtol(tmp, NULL, 16);
    }
    return true;
}

bool buffer2Hex(const unsigned char *buffer, size_t len, char *str) {
    if (NULL == buffer || len == 0 || NULL == str) return false;
    for (size_t i = 0; i < len; ++i) {
        sprintf(str + i * 2, "%02x", buffer[i]);
    }
    return true;
}
