package you.chen.encrypt;

import java.util.Random;

/**
 * author: you : 2019/3/17
 */
public final class Test {

    private Test() {
    }

    static final String abc = "像我这样优秀的人 本该灿烂过一生 संस्कृतम् 각간갈 you do";

    /**
     * 下面的值是通过 pemKey2DerKey 方法生成
     */
    public static String RSA_PUBLIC_KEY = "MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQC2a7bm+na9YhCfiWYZU7x+99MktMW9el8sjd+v0AEtth95Nh/6f7Wzc9ydwsuOJSu8OKDWnTsEYCE4wyJ4Zmw6nCpRYiO1zwgt+dRLm7IIhdcjsI1SjLLyptToJJ1ab2E3dq6Ck1ifMpJ36lj8cLAFLKRqW8edSbf87mFyxYZY/wIBAw==";
    public static String RSA_PRIVATE_KEY = "MIIBNgIBADANBgkqhkiG9w0BAQEFAASCASAwggEcAgEAAoGBALZrtub6dr1iEJ+JZhlTvH730yS0xb16XyyN36/QAS22H3k2H/p/tbNz3J3Cy44lK7w4oNadOwRgITjDInhmbDqcKlFiI7XPCC351EubsgiF1yOwjVKMsvKm1OgknVpvYTd2roKTWJ8yknfqWPxwsAUspGpbx51Jt/zuYXLFhlj/AgEAAoGAeZ0kmfxPKOwLFQZEEOJ9qfqMwyMuflGUyF6VH+AAySQU+3lqpv/Od6KTE9cyXsNyfXsV5GjSAurA0IIW+u7y0Jy+0IJuCTCt7vZwa4v+CA3Qy8sVBkbCve0KaFZIAYmdLKDfPOrKJRrLUVOoEM2oaaVfIvAhwLOqpBUmVwGa/zsCAQACAQACAQACAQACAQA=";

    public static void testBase64() {
        String jniBase64 = Encrypts.base64Encode(abc);
        String jniData = Encrypts.base64Decode(jniBase64);
        LogUtils.i("JniBase64Encode = %s, JniBase64decode = %s", jniBase64, jniData);

        String javaBase = EncryptUtils.base64Encode(abc);
        String javaData = EncryptUtils.base64Decode(javaBase);
        LogUtils.i("JavaBase64Encode = %s, JavaBase64Decode = %s", javaBase, javaData);

        LogUtils.i("encode equals = " + jniBase64.equals(javaBase) + "  decode equals " + jniData.equals(javaData));
    }

    public static void testMD5() {
        String jniMd5 = Encrypts.md5(abc);
        String javaMd5 = EncryptUtils.getMD5(abc);
        LogUtils.i("JniMd5 = %s, JavaMd5 = %s,  == %b", jniMd5, javaMd5, jniMd5.equals(javaMd5));
    }

    public static void testEcbAES() {
        String key = "0123456789abcdefghijklmn";
        try {
            String jniRes = Encrypts.aesEcbEncrypt(abc, key);
            String jniData = Encrypts.aesEcbDecrypt(jniRes, key);
            LogUtils.i("ECB模式 JniAesEnc = %s, JniAesDec = %s", jniRes, jniData);

            String javaRes = EncryptUtils.encryptAES(abc, key);
            String javaData = EncryptUtils.decryptAES(javaRes, key);
            LogUtils.i("ECB模式 JavaAesEnc = %s, JavaAesDec = %s", javaRes, javaData);

            LogUtils.i("ECB模式 enc equals = %b, dec equals = %b", jniRes.equals(javaRes), jniData.equals(javaData));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void testCbcAES() {
        String key = "0123456789abcdefghijklmn";
        String iv = "qwertyuiop123456";
        try {
            String jniRes = Encrypts.aesEncrypt(abc, key, iv);
            String jniData = Encrypts.aesDecrypt(jniRes, key, iv);
            LogUtils.i("CBC模式 JniAesEnc cbc = %s, JniAesDec = %s", jniRes, jniData);

            String javaRes = EncryptUtils.encryptAES(abc, key, iv);
            String javaData = EncryptUtils.decryptAES(javaRes, key, iv);
            LogUtils.i("CBC模式 JavaAesEnc = %s, JavaAesDec = %s", javaRes, javaData);

            LogUtils.i("CBC模式 enc equals = %b, dec equals = %b", jniRes.equals(javaRes), jniData.equals(javaData));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void testRsa() {
        //实际开发中RSA是加密AES的KEY使用, 注意1024生成的KEY加密长度限制
        String data = "ABCDEFGHIJ123456";
        try {
            String jniRsa = Encrypts.rsaEncrypt(data);
            String jniData = Encrypts.rsaDecrypt(jniRsa);
            String javaRsa = EncryptUtils.rsaEncrypt(data, RSA_PUBLIC_KEY);
            String javaData = EncryptUtils.rsaDecrypt(javaRsa, RSA_PRIVATE_KEY);
            LogUtils.i("Jni rsa = %s , Java rsa =  %s ", jniData, javaData);

            //分别用C解密Java加密的数据, 和用Java解密C加密的数据
            String jniDeJavaRsa = Encrypts.rsaDecrypt(javaRsa);
            String javaDeJniRsa = EncryptUtils.rsaDecrypt(jniRsa, RSA_PRIVATE_KEY);
            LogUtils.i("Jni解密Java = %s,  Java解密Jni = %s, 结果是否一致 = %b", jniDeJavaRsa, javaDeJniRsa, jniDeJavaRsa.equals(javaDeJniRsa));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    //自动生成名字（中文）
    public static String getRandomJianHan(int len) {
        Random random = new Random();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len; i++) {
            int hightPos = 176 + Math.abs(random.nextInt(39));
            int lowPos = 161 + Math.abs(random.nextInt(93));
            byte[] b = new byte[2];
            b[0] = new Integer(hightPos).byteValue();
            b[1] = new Integer(lowPos).byteValue();
            try {
                sb.append(new String(b, "GBK"));
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
        return sb.toString();
    }

    static final String CH = "abcdefghijklmnopqrstuvwxyz0123456789";
    //length用户要求产生字符串的长度
    public static String getRandomString(int length) {
        Random random = new Random();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            int number = random.nextInt(36);
            sb.append(CH.charAt(number));
        }
        return sb.toString();
    }

}
