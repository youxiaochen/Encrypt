//
// Created by you on 2019/6/18.
//
#include "MD5Code.h"
#include <openssl/md5.h>

std::string MD5Code::md5(const char *src, size_t src_len) {
    unsigned char md[16];
    MD5((unsigned char *) src, src_len, md);
    char md5str[33]{0};  //MD5结果 32 + \0
    for (int i = 0; i < 16; i++) {
        sprintf(md5str, "%s%02x", md5str, md[i]);
    }
    return md5str;
}
