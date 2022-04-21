//
// Created by you on 2019/4/18.
//
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include "BASE64Code.h"

std::string BASE64Code::encode(const char *src, size_t src_len) {
    BIO *bmem, *b64;
    BUF_MEM *bptr;
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);//不换行
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, src, src_len);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    std::string str_result(bptr->data, bptr->length);

    BIO_free_all(b64);
    return str_result;
}

std::string BASE64Code::decode(const char *src, size_t src_len) {
    BIO *b64, *bmem;
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);//不换行
    bmem = BIO_new_mem_buf(src, src_len);
    bmem = BIO_push(b64, bmem);

    size_t decode_len = src_len * 3 / 4; //解码出的数据长度 <= 原长度 3/4
    std::string str_result(decode_len, 0);
    BIO_read(b64, (void*) str_result.c_str(), decode_len);
    BIO_free_all(bmem);
    return str_result;
}
