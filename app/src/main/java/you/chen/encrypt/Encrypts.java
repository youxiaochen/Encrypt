package you.chen.encrypt;

/**
 * author: you : 2019/4/19
 */
public final class Encrypts {

    static {
        System.loadLibrary("encrypt");
    }

    private Encrypts() {}

    /**
     * BASE64编码
     * @param data
     * @return
     */
    public native static String base64Encode(String data);
    public native static String base64Decode(String data);

    /**
     * md5编码
     * @param data
     * @return
     */
    public native static String md5(String data);

    /**
     * aes ecb加密
     * @param data
     * @param key
     * @return
     */
    public native static String aesEcbEncrypt(String data, String key);
    public native static String aesEcbDecrypt(String data, String key);

    /**
     * AES cbc 加密
     * @param data
     * @param key 密钥
     * @param iv 偏移
     * @return
     */
    public native static String aesEncrypt(String data, String key, String iv);
    public native static String aesDecrypt(String data, String key, String iv);

    /**
     * rsa加密 key在JNI层
     * @param data
     * @return
     */
    public native static String rsaEncrypt(String data);
    public native static String rsaDecrypt(String data);

    /**
     * 生成RSA 公私钥, JNI生成的PEM格式的, Java层不能直接使用,需要转换, Service中已经实现
     */
    public native static String createRsaKey();
}
