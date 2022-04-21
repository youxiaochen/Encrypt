//
// Created by you on 2019/6/18.
//

#ifndef ENCRYPT_MD5CODE_H
#define ENCRYPT_MD5CODE_H

#include <string>

class MD5Code{

public:

    /**
     * md5算法
     * @param src
     * @param src_len
     * @return
     */
    static std::string md5(const char *src, size_t src_len);

};

#endif //ENCRYPT_MD5CODE_H
