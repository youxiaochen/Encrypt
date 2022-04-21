package you.chen.encrypt;

import android.util.Base64;

import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * author: you : 2019/3/17
 */
public final class EncryptUtils {

    private EncryptUtils() {}

    static final String UTF8 = "UTF-8";

    private static final char HEX_DIGITS[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    /**
     * base64编码
     * @param data
     * @return
     */
    public static String base64Encode(String data) {
        try {
            return new String(Base64.encode(data.getBytes(UTF8), Base64.NO_WRAP));
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * base64解码
     * @param data
     * @return
     */
    public static String base64Decode(String data) {
        try {
            return new String(Base64.decode(data.getBytes(), Base64.NO_WRAP));
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * md5加密
     * @param instr
     * @return 十六进制
     */
    public static String getMD5(String instr) {
        if (instr == null) return null;
        try {
            byte[] btInput = instr.getBytes(UTF8);
            MessageDigest mdInst = MessageDigest.getInstance("MD5");
            mdInst.update(btInput);
            byte[] md = mdInst.digest();
            // 把密文转换成十六进制的字符串形式
            int j = md.length;
            char str[] = new char[j * 2];
            int k = 0;
            for (int i = 0; i < j; i++) {
                byte byte0 = md[i];
                str[k++] = HEX_DIGITS[byte0 >> 4 & 0xf];
                str[k++] = HEX_DIGITS[byte0 & 0xf];
            }
            return new String(str);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 对称AES加密 CBC方式
     * @param content
     * @param key 128 192 256位  即Key长度为 16, 24， 32
     * @return
     */
    public static String encryptAES(String content, String key, String iv) {
        try {
            byte[] byteContent = content.getBytes(UTF8);
            byte[] enCodeFormat = key.getBytes();
            SecretKeySpec secretKeySpec = new SecretKeySpec(enCodeFormat, "AES");
            byte[] initParam = iv.getBytes();
            IvParameterSpec ivParameterSpec = new IvParameterSpec(initParam);
            // 指定加密的算法、工作模式和填充方式
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
            byte[] encryptedBytes = cipher.doFinal(byteContent);
            return Base64.encodeToString(encryptedBytes, Base64.NO_WRAP);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 对称AES解密 CBC方式
     * @param content
     * @param key  128 192 256位  即Key长度为 16, 24， 32
     * @return
     */
    public static String decryptAES(String content, String key, String iv) {
        try {
            byte[] encryptedBytes = Base64.decode(content.getBytes(), Base64.NO_WRAP);
            byte[] enCodeFormat = key.getBytes();
            SecretKeySpec secretKey = new SecretKeySpec(enCodeFormat, "AES");
            byte[] initParam = iv.getBytes();
            IvParameterSpec ivParameterSpec = new IvParameterSpec(initParam);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
            byte[] result = cipher.doFinal(encryptedBytes);
            return new String(result, UTF8);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 对称AES加密 ECB方式
     * @param content
     * @param key 128 192 256位  即Key长度为 16, 24， 32
     * @return
     */
    public static String encryptAES(String content, String key) {
        try {
            byte[] byteContent = content.getBytes("UTF-8");
            byte[] enCodeFormat = key.getBytes();
            SecretKeySpec secretKeySpec = new SecretKeySpec(enCodeFormat, "AES");
            // 指定加密的算法、工作模式和填充方式
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            byte[] encryptedBytes = cipher.doFinal(byteContent);
            return Base64.encodeToString(encryptedBytes, Base64.NO_WRAP);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 对称AES解密  ECB方式
     * @param content
     * @param key  128 192 256位  即Key长度为 16, 24， 32
     * @return
     */
    public static String decryptAES(String content, String key) {
        try {
            byte[] encryptedBytes = Base64.decode(content.getBytes(), Base64.NO_WRAP);
            byte[] enCodeFormat = key.getBytes();
            SecretKeySpec secretKey = new SecretKeySpec(enCodeFormat, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] result = cipher.doFinal(encryptedBytes);
            return new String(result, UTF8);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 如果需要在后台使用将Base64换成后台的Base64即可
     * rsa加密
     * @param source  加密的数据为AES key
     * @param pub_key 公钥
     * @return
     */
    public static String rsaEncrypt(String source, String pub_key) {
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.decode(pub_key.getBytes(), Base64.NO_WRAP));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(keySpec);

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] bs = cipher.doFinal(source.getBytes(UTF8));
            return Base64.encodeToString(bs, Base64.NO_WRAP);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 如果需要在后台使用将Base64换成后台的Base64即可
     * rsa解密
     * @param rsa
     * @param pri_key 私钥
     * @return
     */
    public static String rsaDecrypt(String rsa, String pri_key) {
        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.decode(pri_key.getBytes(), Base64.NO_WRAP));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] b = cipher.doFinal(Base64.decode(rsa.getBytes(), Base64.NO_WRAP));
            return new String(b, UTF8);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }



}
