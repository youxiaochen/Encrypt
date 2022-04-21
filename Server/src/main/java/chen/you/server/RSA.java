package chen.you.server;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;

/**
 * author: you : 2019/6/17
 */
public final class RSA {

    private RSA() {}

    public static final String CHAR_ENCODING = "UTF-8";

    public static final String RSA_ALGORITHM = "RSA/ECB/PKCS1Padding";

    public static String RSA_PUBLIC_KEY = "MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQC2a7bm+na9YhCfiWYZU7x+99MktMW9el8sjd+v0AEtth95Nh/6f7Wzc9ydwsuOJSu8OKDWnTsEYCE4wyJ4Zmw6nCpRYiO1zwgt+dRLm7IIhdcjsI1SjLLyptToJJ1ab2E3dq6Ck1ifMpJ36lj8cLAFLKRqW8edSbf87mFyxYZY/wIBAw==";
    public static String RSA_PRIVATE_KEY = "MIIBNgIBADANBgkqhkiG9w0BAQEFAASCASAwggEcAgEAAoGBALZrtub6dr1iEJ+JZhlTvH730yS0xb16XyyN36/QAS22H3k2H/p/tbNz3J3Cy44lK7w4oNadOwRgITjDInhmbDqcKlFiI7XPCC351EubsgiF1yOwjVKMsvKm1OgknVpvYTd2roKTWJ8yknfqWPxwsAUspGpbx51Jt/zuYXLFhlj/AgEAAoGAeZ0kmfxPKOwLFQZEEOJ9qfqMwyMuflGUyF6VH+AAySQU+3lqpv/Od6KTE9cyXsNyfXsV5GjSAurA0IIW+u7y0Jy+0IJuCTCt7vZwa4v+CA3Qy8sVBkbCve0KaFZIAYmdLKDfPOrKJRrLUVOoEM2oaaVfIvAhwLOqpBUmVwGa/zsCAQACAQACAQACAQACAQA=";

    /**
     * RSA加密
     * @param source
     * @param pubKey
     * @return
     * @throws Exception
     */
    public static String encrypt(String source, String pubKey) {
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.decodeBase64(pubKey.getBytes()));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(keySpec);

            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] b1 = cipher.doFinal(source.getBytes(CHAR_ENCODING));
            return new String(Base64.encodeBase64(b1));
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

    }

    /**
     * RSA解密
     * @param rsaData
     * @param priKey
     * @return
     * @throws Exception
     */
    public static String decrypt(String rsaData, String priKey) {
        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(priKey.getBytes()));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] b = cipher.doFinal(Base64.decodeBase64(rsaData.getBytes()));
            return new String(b, CHAR_ENCODING);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * RSA 公钥私钥对象
     */
    public static class RSAKey {

        public String publicKey;

        public String privateKey;

        public String modulus;
    }

    /**
     * 指定key的大小
     */
    private static int KEYSIZE = 1024;

    /**
     * 生成密钥对
     */
    public static RSAKey generateKeyPair() throws Exception {
        //默认加密位数
        return generateKeyPair(KEYSIZE);
    }

    /**
     * 生成密钥对
     */
    public static RSAKey generateKeyPair(int keySize) throws Exception {
        SecureRandom sr = new SecureRandom();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(keySize, sr);
        KeyPair kp = kpg.generateKeyPair();
        Key publicKey = kp.getPublic();
        byte[] publicKeyBytes = publicKey.getEncoded();
        String pub = new String(Base64.encodeBase64(publicKeyBytes), CHAR_ENCODING);
        Key privateKey = kp.getPrivate();
        byte[] privateKeyBytes = privateKey.getEncoded();
        String pri = new String(Base64.encodeBase64(privateKeyBytes), CHAR_ENCODING);

        Map<String, String> map = new HashMap<String, String>();
        map.put("publicKey", pub);
        map.put("privateKey", pri);
        RSAPublicKey rsp = (RSAPublicKey) kp.getPublic();
        BigInteger bint = rsp.getModulus();
        byte[] b = bint.toByteArray();
        byte[] deBase64Value = Base64.encodeBase64(b);
        String retValue = new String(deBase64Value);
        map.put("modulus", retValue);

        RSAKey rsaKey = new RSAKey();
        rsaKey.modulus = retValue;
        rsaKey.publicKey = pub;
        rsaKey.privateKey = pri;
        return rsaKey;
    }

}