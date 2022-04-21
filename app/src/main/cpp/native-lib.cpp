#include <jni.h>
#include <string>

#include "Log.h"
#include "BASE64Code.h"
#include "MD5Code.h"
#include "AESCrypto.h"
#include "RSACrypto.h"

using namespace std;

//rsa keys
#define PUBLICKEY "-----BEGIN RSA PUBLIC KEY-----\nMIGHAoGBALZrtub6dr1iEJ+JZhlTvH730yS0xb16XyyN36/QAS22H3k2H/p/tbNz\n3J3Cy44lK7w4oNadOwRgITjDInhmbDqcKlFiI7XPCC351EubsgiF1yOwjVKMsvKm\n1OgknVpvYTd2roKTWJ8yknfqWPxwsAUspGpbx51Jt/zuYXLFhlj/AgED\n-----END RSA PUBLIC KEY-----"
#define PRIVATE_KEY "-----BEGIN RSA PRIVATE KEY-----\nMIICWwIBAAKBgQC2a7bm+na9YhCfiWYZU7x+99MktMW9el8sjd+v0AEtth95Nh/6\nf7Wzc9ydwsuOJSu8OKDWnTsEYCE4wyJ4Zmw6nCpRYiO1zwgt+dRLm7IIhdcjsI1S\njLLyptToJJ1ab2E3dq6Ck1ifMpJ36lj8cLAFLKRqW8edSbf87mFyxYZY/wIBAwKB\ngHmdJJn8TyjsCxUGRBDifan6jMMjLn5RlMhelR/gAMkkFPt5aqb/zneikxPXMl7D\ncn17FeRo0gLqwNCCFvru8tCcvtCCbgkwre72cGuL/ggN0MvLFQZGwr3tCmhWSAGJ\nnSyg3zzqyiUay1FTqBDNqGmlXyLwIcCzqqQVJlcBmv87AkEA5grvj0F75uSHzzOn\n90FSim17VXWNVzr7iSerg6nAFnrTqk/dOe0/KYQ1O9gi1ZWvPPFdpI+YRbCfZaOi\nBpI6PQJBAMsBKQ89LB8ev7j4AlJzqeawdqp4O8tT2jodoB+HmAp6oNsPyfk8KGDd\nSLEEwGadt3ekWE8FY/aHZ2kETjyLn+sCQQCZXJ+01lKZ7a/fd8VPgOGxnlI4+Qjk\n0f0GGnJXxoAO/I0cNT4mniobrXjSkBc5DnTTS5PDCmWDyxTubRavDCbTAkEAh1Yb\nX34dahR/0KVW4aJxRHWkcaV9Mjfm0WkValplXFHAkgqGpiga6z4wdgMq7xPPpRg6\n31jtTwTvm1g0KF0VRwJAY0rj3NWey/4apiEdrNV143w83iQtFTDliKXB8voAxk6y\npZkunO7IzRcbnC2+132e0/G9LdLGbVqgHO4i2leMYw==\n-----END RSA PRIVATE KEY-----"

//ECC KEY
static const char *publicKey_ = "572d1e2710ae5fbca54c76a382fdd44050b3a675cb2bf39feebe85ef63d947aff0fa4943f1112e8b6af34bebebbaefa1a0aae055d9259b89a1858f7cc9af9df1";
static const char *privateKey_ = "145aa7717bf9745b91e9569b80bbf1eedaa6cc6cd0e26317d810e35710f44cf8";

extern "C" JNIEXPORT jstring JNICALL
Java_you_chen_encrypt_Encrypts_base64Encode(JNIEnv *env, jclass clazz, jstring _data) {
    const char *data = env->GetStringUTFChars(_data, JNI_FALSE);
    string result = BASE64Code::encode(data, strlen(data));
    env->ReleaseStringUTFChars(_data, data);
    return env->NewStringUTF(result.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_you_chen_encrypt_Encrypts_base64Decode(JNIEnv *env, jclass clazz, jstring _data) {
    const char *data = env->GetStringUTFChars(_data, JNI_FALSE);
    string result = BASE64Code::decode(data, strlen(data));
    env->ReleaseStringUTFChars(_data, data);
    return env->NewStringUTF(result.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_you_chen_encrypt_Encrypts_md5(JNIEnv *env, jclass clazz, jstring _data) {
    const char *data = env->GetStringUTFChars(_data, JNI_FALSE);
    string md5_str = MD5Code::md5(data, strlen(data));
    env->ReleaseStringUTFChars(_data, data);
    return env->NewStringUTF(md5_str.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_you_chen_encrypt_Encrypts_aesEcbEncrypt(JNIEnv *env, jclass clazz, jstring _data, jstring _key) {
    const char *data = env->GetStringUTFChars(_data, JNI_FALSE);
    const char *key = env->GetStringUTFChars(_key, JNI_FALSE);

    string aes_res = AESCrypto::ecb_encrypt(data, (unsigned char*) key, strlen(key), PaddingModel::PKCS5OR7);
    string base_res = BASE64Code::encode(aes_res.c_str(), aes_res.length());

    env->ReleaseStringUTFChars(_data, data);
    env->ReleaseStringUTFChars(_key, key);
    return env->NewStringUTF(base_res.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_you_chen_encrypt_Encrypts_aesEcbDecrypt(JNIEnv *env, jclass clazz, jstring _data, jstring _key) {
    const char *data = env->GetStringUTFChars(_data, JNI_FALSE);
    const char *key = env->GetStringUTFChars(_key, JNI_FALSE);

    string base_res = BASE64Code::decode(data, strlen(data));
    string aes_res = AESCrypto::ecb_decrypt(base_res.c_str(), base_res.length(), (unsigned char*) key, strlen(key));

    env->ReleaseStringUTFChars(_data, data);
    env->ReleaseStringUTFChars(_key, key);
    return env->NewStringUTF(aes_res.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_you_chen_encrypt_Encrypts_aesEncrypt(JNIEnv *env, jclass clazz, jstring _data, jstring _key, jstring _iv) {
    const char *data = env->GetStringUTFChars(_data, JNI_FALSE);
    const char *key = env->GetStringUTFChars(_key, JNI_FALSE);
    const char *iv = env->GetStringUTFChars(_iv, JNI_FALSE);

    //最好确认偏移量
    unsigned char ivs[16] = {0};
    memcpy(ivs, iv, env->GetStringLength(_iv));
    string aes_res = AESCrypto::cbc_encrypt(data, (unsigned char*) key, strlen(key), ivs, PaddingModel::PKCS5OR7);
    string base_res = BASE64Code::encode(aes_res.c_str(), aes_res.length());

    env->ReleaseStringUTFChars(_data, data);
    env->ReleaseStringUTFChars(_key, key);
    env->ReleaseStringUTFChars(_iv, iv);
    return env->NewStringUTF(base_res.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_you_chen_encrypt_Encrypts_aesDecrypt(JNIEnv *env, jclass clazz, jstring _data, jstring _key, jstring _iv) {
    const char *data = env->GetStringUTFChars(_data, JNI_FALSE);
    const char *key = env->GetStringUTFChars(_key, JNI_FALSE);
    const char *iv = env->GetStringUTFChars(_iv, JNI_FALSE);

    unsigned char ivs[16] = {0};
    memcpy(ivs, iv, env->GetStringLength(_iv));
    string base_res = BASE64Code::decode(data, strlen(data));
    string aes_res = AESCrypto::cbc_decrypt(base_res.c_str(), base_res.length(), (unsigned char*) key, strlen(key), ivs);

    env->ReleaseStringUTFChars(_data, data);
    env->ReleaseStringUTFChars(_key, key);
    env->ReleaseStringUTFChars(_iv, iv);
    return env->NewStringUTF(aes_res.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_you_chen_encrypt_Encrypts_rsaEncrypt(JNIEnv *env, jclass clazz, jstring _data) {
    const char *data = env->GetStringUTFChars(_data, JNI_FALSE);

    string rsa_ret = RSACrypto::encrypt((unsigned char*) data, strlen(data),
            (const unsigned char *) PUBLICKEY, strlen(PUBLICKEY));
    string result = BASE64Code::encode(rsa_ret.c_str(), rsa_ret.length());

    env->ReleaseStringUTFChars(_data, data);
    return env->NewStringUTF(result.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_you_chen_encrypt_Encrypts_rsaDecrypt(JNIEnv *env, jclass clazz, jstring _data) {
    const char *data = env->GetStringUTFChars(_data, JNI_FALSE);
    string base_data = BASE64Code::decode(data, strlen(data));
    string rsa_ret = RSACrypto::decrypt((unsigned char*) base_data.c_str(), base_data.length(),
            (const unsigned char *) PRIVATE_KEY, strlen(PRIVATE_KEY));
    env->ReleaseStringUTFChars(_data, data);
    return env->NewStringUTF(rsa_ret.c_str());
}


extern "C" JNIEXPORT jstring JNICALL
Java_you_chen_encrypt_Encrypts_eccEncrypt(JNIEnv *env, jclass clazz, jstring _data, jstring _key) {
    const char *data = env->GetStringUTFChars(_data, JNI_FALSE);
    const char *key = env->GetStringUTFChars(_key, JNI_FALSE);



    env->ReleaseStringUTFChars(_data, data);
    env->ReleaseStringUTFChars(_key, key);
    return env->NewStringUTF("AAA");
}

extern "C"
JNIEXPORT void JNICALL
Java_you_chen_encrypt_Encrypts_test(JNIEnv *env, jclass clazz, jstring _path) {
    const char *path = env->GetStringUTFChars(_path, JNI_FALSE);
    LOGD("str len %s - %d", path, strlen(path));

    string pub_key, pri_key;
    RSACrypto::createRSAKey(pub_key, pri_key);
    LOGD("public = %s", pub_key.c_str());
    LOGD("private = %s", pri_key.c_str());
    LOGD("public len = %d", pub_key.length());
    LOGD("private len = %d", pri_key.length());



    env->ReleaseStringUTFChars(_path, path);
}