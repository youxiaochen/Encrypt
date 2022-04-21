//
// Created by you on 2019/6/19.
//
#include "RSACrypto.h"
#include <openssl/evp.h>
#include <openssl/pem.h>

std::string RSACrypto::encrypt(const unsigned char *src, size_t src_len,
                               const unsigned char *pub_key, size_t key_len) {
    BIO *keybio = nullptr;
    keybio = BIO_new_mem_buf(pub_key, key_len);
    if (keybio == nullptr) {
//        LOGD("init key error null");
        return "";
    }
    RSA *rsa = nullptr;
    rsa = PEM_read_bio_RSAPublicKey(keybio, nullptr, nullptr, nullptr);
    if (rsa == nullptr) {
//        LOGD("init RSA error null");
        BIO_free_all(keybio);
        return "";
    }

    int len = RSA_size(rsa);
    std::string rsa_ret(len, 0);
    int ret = RSA_public_encrypt(src_len, src, (unsigned char *)rsa_ret.c_str(), rsa, RSA_PKCS1_PADDING);
    RSA_free(rsa);
    BIO_free_all(keybio);
    CRYPTO_cleanup_all_ex_data();
    if (ret > 0) return rsa_ret;
    return "";
}

std::string RSACrypto::decrypt(const unsigned char *src, size_t src_len,
        const unsigned char *pri_key, size_t key_len) {
    BIO *keybio = nullptr;
    keybio = BIO_new_mem_buf(pri_key, key_len);
    if (keybio == nullptr) {
//        LOGD("init key error null");
        return "";
    }
    RSA *rsa = nullptr;
    rsa = PEM_read_bio_RSAPrivateKey(keybio, nullptr, nullptr, nullptr);
    if (rsa == nullptr) {
//        LOGD("init RSA error null");
        BIO_free_all(keybio);
        return "";
    }
    int len = RSA_size(rsa);
    std::string rsa_ret(len, 0);
    int ret = RSA_private_decrypt(len, src, (unsigned char *)rsa_ret.c_str(), rsa, RSA_PKCS1_PADDING);
    RSA_free(rsa);
    BIO_free_all(keybio);
    CRYPTO_cleanup_all_ex_data();
    if (ret > 0) return rsa_ret;
    return "";
}

void RSACrypto::createRSAKey(std::string &pub_key_str, std::string &pri_key_str) {
    RSA *rsa = RSA_generate_key(1024, RSA_3, nullptr, nullptr);
    if (!rsa) {
        pub_key_str.assign("ras init error");
        pri_key_str.assign("ras init error");
        return;
    }
    // 生成私公钥
    BIO *pri_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(pri_bio, rsa, NULL, NULL, 0, NULL, NULL);
    BIO *pub_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(pub_bio, rsa);

    //获取长度并读取
    size_t pri_len = BIO_pending(pri_bio);
    size_t pub_len = BIO_pending(pub_bio);
    //对应RSA_generate_key(1024...)
    char pri_key[1024]{0};
    char pub_key[512]{0};
    BIO_read(pri_bio, pri_key, pri_len);
    BIO_read(pub_bio, pub_key, pub_len);

    //释放资源
//    RSA_free(rsa);
    BIO_free_all(pri_bio);
    BIO_free_all(pub_bio);
    CRYPTO_cleanup_all_ex_data();

    pub_key_str.assign(pub_key, pub_len);
    pri_key_str.assign(pri_key, pri_len);
}