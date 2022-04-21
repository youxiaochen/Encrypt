//
// Created by you on 2019/6/19.
//

#ifndef ENCRYPT_PADING_H
#define ENCRYPT_PADING_H

#include <string>

/**
 * 填充模式
 */
enum PaddingModel {
    ZERO,  //ZERO pading
    PKCS5OR7 //pkcs5 pkcs7 padding
};

class Padding {

public:

    /**
     * 填充数据源
     * @param src
     * @param alignSize
     * @param mode
     */
    static void padding(std::string &src, int alignSize, PaddingModel mode);

    static void unpadding(std::string &src);

};

#endif //ENCRYPT_PADING_H
