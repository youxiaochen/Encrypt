//
// Created by you on 2019/6/18.
//
#include "AESCrypto.h"
#include <openssl/aes.h>

std::string AESCrypto::cbc_encrypt(const char *src,
                                  const unsigned char *key, size_t key_len,
                                  unsigned char *iv,
                                  PaddingModel mode) {
    AES_KEY aes_key;
    std::string str_result;
    if (AES_set_encrypt_key(key, key_len * 8, &aes_key) == 0) {
        std::string str_data = src;
        Padding::padding(str_data, AES_BLOCK_SIZE, mode);

        unsigned char out[AES_BLOCK_SIZE]{0};
        int blockSize = str_data.length() / AES_BLOCK_SIZE;
        for (int i = 0; i < blockSize; ++i) {
            const unsigned char *in = (const unsigned char *) str_data.c_str() + i * AES_BLOCK_SIZE;
            AES_cbc_encrypt(in, out, AES_BLOCK_SIZE, &aes_key, iv, AES_ENCRYPT);
            str_result += std::string((const char *) out, AES_BLOCK_SIZE);
            memset(out, 0, AES_BLOCK_SIZE);
        }
    }
    return str_result;
}

std::string AESCrypto::cbc_decrypt(const char *src, size_t src_len,
                                  const unsigned char *key, size_t key_len,
                                  unsigned char *iv) {
    AES_KEY aes_key;
    std::string str_result;
    if (AES_set_decrypt_key(key, key_len * 8, &aes_key) == 0) {
        unsigned char out[AES_BLOCK_SIZE]{0};
        int blockSize = src_len / AES_BLOCK_SIZE;
        for (int i = 0; i < blockSize; ++i) {
            const unsigned char *in = (const unsigned char *) src + i * AES_BLOCK_SIZE;
            AES_cbc_encrypt(in, out, AES_BLOCK_SIZE, &aes_key, iv, AES_DECRYPT);
            str_result += std::string((const char *) out, AES_BLOCK_SIZE);
            memset(out, 0, AES_BLOCK_SIZE);
        }
        Padding::unpadding(str_result);
    }
    return str_result;
}

std::string AESCrypto::ecb_encrypt(const char *src,
                                  const unsigned char *key, size_t key_len,
                                  PaddingModel mode) {
    AES_KEY aes_key;
    std::string str_result;
    if (AES_set_encrypt_key(key, key_len * 8, &aes_key) == 0) {
        std::string str_data = src;
        Padding::padding(str_data, AES_BLOCK_SIZE, mode);

        unsigned char out[AES_BLOCK_SIZE]{0};
        int blockSize = str_data.length() / AES_BLOCK_SIZE;
        for (int i = 0; i < blockSize; ++i) {
            const unsigned char *in = (const unsigned char *) str_data.c_str() + i * AES_BLOCK_SIZE;
            AES_ecb_encrypt(in, out, &aes_key, AES_ENCRYPT);
            str_result += std::string((const char *) out, AES_BLOCK_SIZE);
            memset(out, 0, AES_BLOCK_SIZE);
        }
    }
    return str_result;
}

std::string AESCrypto::ecb_decrypt(const char *src, size_t src_len,
                                  const unsigned char *key, size_t key_len) {
    AES_KEY aes_key;
    std::string str_result;
    if (AES_set_decrypt_key(key, key_len * 8, &aes_key) == 0) {
        unsigned char out[AES_BLOCK_SIZE]{0};
        int blockSize = src_len / AES_BLOCK_SIZE;
        for (int i = 0; i < blockSize; ++i) {
            const unsigned char *in = (const unsigned char *) src + i * AES_BLOCK_SIZE;
            AES_ecb_encrypt(in, out, &aes_key, AES_DECRYPT);
            str_result += std::string((const char *) out, AES_BLOCK_SIZE);
            memset(out, 0, AES_BLOCK_SIZE);
        }
        Padding::unpadding(str_result);
    }
    return str_result;
}
