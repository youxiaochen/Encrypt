package chen.you.server;

public class JavaTest {

    public static void main(String[] args) {
//        KeyUtils.pemKey2DerKey();  转化 openssl生成的KEY


        testRsa();
    }

    //测试JAVA的RSA加密解密
    static void testRsa() {
        String aesKeyData = "0123456789abcdef";
        String rsaRes = RSA.encrypt(aesKeyData, RSA.RSA_PUBLIC_KEY);
        String data = RSA.decrypt(rsaRes, RSA.RSA_PRIVATE_KEY);
        System.out.println(data + "  " +aesKeyData.equals(data));
    }

}