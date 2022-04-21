//
// Created by you on 2019/6/19.
//
#ifndef ENCRYPT_RSACRYPTO_H
#define ENCRYPT_RSACRYPTO_H

#include <string>

class RSACrypto {

public:

    /**
     * rsa加密
     * @param src
     * @param src_len
     * @param pub_key PEM格式公钥
     * @param key_len
     * @return
     */
    static std::string encrypt(const unsigned char *src, size_t src_len,
                               const unsigned char *pub_key, size_t key_len);

    /**
     * RSA解密
     * @param src
     * @param src_len
     * @param pri_key PEM格式的密钥
     * @param key_len
     * @return
     */
    static std::string decrypt(const unsigned char *src, size_t src_len,
                               const unsigned char *pri_key, size_t key_len);
    /**
     * 生成PEM格式 公,私钥  注意 \n字符
     * @param pub_key_str
     * @param pri_key_str
     */
    static void createRSAKey(std::string &pub_key_str, std::string &pri_key_str);
};

#endif //ENCRYPT_RSACRYPTO_H
