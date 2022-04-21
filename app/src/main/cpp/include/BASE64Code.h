//
// Created by you on 2019/6/18.
//

#ifndef ENCRYPT_BASE64CODE_H
#define ENCRYPT_BASE64CODE_H

#include <string>

class BASE64Code {

public:

    /**
     * base64编码
     * @param src
     * @param src_len
     * @return
     */
    static std::string encode(const char *src, size_t src_len);

    /**
     * base64解码
     * @param src
     * @param src_len
     * @return
     */
    static std::string decode(const char *src, size_t src_len);

};

#endif //ENCRYPT_BASE64CODE_H
