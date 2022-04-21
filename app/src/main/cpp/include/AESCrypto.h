//
// Created by you on 2019/6/18.
//

#ifndef ENCRYPT_AESCRYPTO_H
#define ENCRYPT_AESCRYPTO_H

#include <string>
#include "Pading.h"

class AESCrypto {

public:

    /**
     * cbc 模式加密
     * @param src
     * @param key
     * @param key_len
     * @param iv
     * @param mode
     * @return
     */
    static std::string cbc_encrypt(const char *src,
                                   const unsigned char *key, size_t key_len,
                                   unsigned char *iv,
                                   PaddingModel mode = ZERO);

    /**
     * CBC解密
     * @param src
     * @param src_len
     * @param key
     * @param key_len
     * @param iv
     * @return
     */
    static std::string cbc_decrypt(const char *src, size_t src_len,
                                   const unsigned char *key, size_t key_len,
                                   unsigned char *iv);

    /**
     * ecb 加密
     * @param src
     * @param key
     * @param key_len
     * @param mode
     * @return
     */
    static std::string ecb_encrypt(const char *src,
                                   const unsigned char *key, size_t key_len,
                                   PaddingModel mode = ZERO);

    /**
     * ecb解密
     * @param src
     * @param src_len
     * @param key
     * @param key_len
     * @return
     */
    static std::string ecb_decrypt(const char *src, size_t src_len,
                                   const unsigned char *key, size_t key_len);
};

#endif //ENCRYPT_AESCRYPTO_H
