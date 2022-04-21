package chen.you.server;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.pkcs.RSAPrivateKeyStructure;
import org.bouncycastle.asn1.x509.RSAPublicKeyStructure;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

/**
 * author: you : 2019/6/20
 */
public final class KeyUtils {

//    #define PUBLICKEY "-----BEGIN RSA PUBLIC KEY-----\nMIGHAoGBALZrtub6dr1iEJ+JZhlTvH730yS0xb16XyyN36/QAS22H3k2H/p/tbNz\n3J3Cy44lK7w4oNadOwRgITjDInhmbDqcKlFiI7XPCC351EubsgiF1yOwjVKMsvKm\n1OgknVpvYTd2roKTWJ8yknfqWPxwsAUspGpbx51Jt/zuYXLFhlj/AgED\n-----END RSA PUBLIC KEY-----"
//    #define PRIVATE_KEY "-----BEGIN RSA PRIVATE KEY-----\nMIICWwIBAAKBgQC2a7bm+na9YhCfiWYZU7x+99MktMW9el8sjd+v0AEtth95Nh/6\nf7Wzc9ydwsuOJSu8OKDWnTsEYCE4wyJ4Zmw6nCpRYiO1zwgt+dRLm7IIhdcjsI1S\njLLyptToJJ1ab2E3dq6Ck1ifMpJ36lj8cLAFLKRqW8edSbf87mFyxYZY/wIBAwKB\ngHmdJJn8TyjsCxUGRBDifan6jMMjLn5RlMhelR/gAMkkFPt5aqb/zneikxPXMl7D\ncn17FeRo0gLqwNCCFvru8tCcvtCCbgkwre72cGuL/ggN0MvLFQZGwr3tCmhWSAGJ\nnSyg3zzqyiUay1FTqBDNqGmlXyLwIcCzqqQVJlcBmv87AkEA5grvj0F75uSHzzOn\n90FSim17VXWNVzr7iSerg6nAFnrTqk/dOe0/KYQ1O9gi1ZWvPPFdpI+YRbCfZaOi\nBpI6PQJBAMsBKQ89LB8ev7j4AlJzqeawdqp4O8tT2jodoB+HmAp6oNsPyfk8KGDd\nSLEEwGadt3ekWE8FY/aHZ2kETjyLn+sCQQCZXJ+01lKZ7a/fd8VPgOGxnlI4+Qjk\n0f0GGnJXxoAO/I0cNT4mniobrXjSkBc5DnTTS5PDCmWDyxTubRavDCbTAkEAh1Yb\nX34dahR/0KVW4aJxRHWkcaV9Mjfm0WkValplXFHAkgqGpiga6z4wdgMq7xPPpRg6\n31jtTwTvm1g0KF0VRwJAY0rj3NWey/4apiEdrNV143w83iQtFTDliKXB8voAxk6y\npZkunO7IzRcbnC2+132e0/G9LdLGbVqgHO4i2leMYw==\n-----END RSA PRIVATE KEY-----"

    /**
     * 下面的key是 C端生成的openssl的KEY, 是PEM需要转换成der
     */
    private static final String  PUBLICKEY =  "MIGHAoGBALZrtub6dr1iEJ+JZhlTvH730yS0xb16XyyN36/QAS22H3k2H/p/tbNz\n3J3Cy44lK7w4oNadOwRgITjDInhmbDqcKlFiI7XPCC351EubsgiF1yOwjVKMsvKm\n1OgknVpvYTd2roKTWJ8yknfqWPxwsAUspGpbx51Jt/zuYXLFhlj/AgED";
    private static final String  PRIVATE_KEY = "MIICWwIBAAKBgQC2a7bm+na9YhCfiWYZU7x+99MktMW9el8sjd+v0AEtth95Nh/6\nf7Wzc9ydwsuOJSu8OKDWnTsEYCE4wyJ4Zmw6nCpRYiO1zwgt+dRLm7IIhdcjsI1S\njLLyptToJJ1ab2E3dq6Ck1ifMpJ36lj8cLAFLKRqW8edSbf87mFyxYZY/wIBAwKB\ngHmdJJn8TyjsCxUGRBDifan6jMMjLn5RlMhelR/gAMkkFPt5aqb/zneikxPXMl7D\ncn17FeRo0gLqwNCCFvru8tCcvtCCbgkwre72cGuL/ggN0MvLFQZGwr3tCmhWSAGJ\nnSyg3zzqyiUay1FTqBDNqGmlXyLwIcCzqqQVJlcBmv87AkEA5grvj0F75uSHzzOn\n90FSim17VXWNVzr7iSerg6nAFnrTqk/dOe0/KYQ1O9gi1ZWvPPFdpI+YRbCfZaOi\nBpI6PQJBAMsBKQ89LB8ev7j4AlJzqeawdqp4O8tT2jodoB+HmAp6oNsPyfk8KGDd\nSLEEwGadt3ekWE8FY/aHZ2kETjyLn+sCQQCZXJ+01lKZ7a/fd8VPgOGxnlI4+Qjk\n0f0GGnJXxoAO/I0cNT4mniobrXjSkBc5DnTTS5PDCmWDyxTubRavDCbTAkEAh1Yb\nX34dahR/0KVW4aJxRHWkcaV9Mjfm0WkValplXFHAkgqGpiga6z4wdgMq7xPPpRg6\n31jtTwTvm1g0KF0VRwJAY0rj3NWey/4apiEdrNV143w83iQtFTDliKXB8voAxk6y\npZkunO7IzRcbnC2+132e0/G9LdLGbVqgHO4i2leMYw==";


    private KeyUtils() {}

    /**
     * 将openssl生成的pem key转成java的der格式的key,  将 -----BEGIN RSA PUBLIC KEY----- 与结尾去除即可
     */
    public static void pemKey2DerKey() {
        try {
            PrivateKey privateKey = KeyUtils.getFromPemPrivateKey(PRIVATE_KEY);
            PublicKey publicKey = KeyUtils.getFromPemPublicKey(PUBLICKEY);

            String der_publicKey = new String(Base64.encodeBase64(publicKey.getEncoded()));
            String der_privateKey = new String(Base64.encodeBase64(privateKey.getEncoded()));

            //这就是JAVA端的DER公钥与私钥
            System.out.println(der_publicKey + "   " + der_privateKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 转换PEM公钥
     * @param public_key
     * @return
     * @throws Exception
     */
    public static PublicKey getFromPemPublicKey(String public_key) throws Exception {
        byte[] keyBytes = new sun.misc.BASE64Decoder().decodeBuffer(public_key);
        ASN1InputStream in = new ASN1InputStream(keyBytes);
        DERObject obj = in.readObject();
        RSAPublicKeyStructure pStruct = RSAPublicKeyStructure.getInstance(obj);
        RSAPublicKeySpec spec = new RSAPublicKeySpec(pStruct.getModulus(), pStruct.getPublicExponent());
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    /**
     * 转换PEM私钥成
     * @param pri_key
     * @return
     * @throws Exception
     */

    public static PrivateKey getFromPemPrivateKey(String pri_key) throws Exception {
        byte[] keyBytes = new sun.misc.BASE64Decoder().decodeBuffer(pri_key);
        ASN1InputStream in = new ASN1InputStream(keyBytes);
        DERObject obj = in.readObject();
        RSAPrivateKeyStructure pstruct = RSAPrivateKeyStructure.getInstance(obj);
        RSAPrivateKeySpec spec = new RSAPrivateKeySpec(pstruct.getModulus(), pstruct.getPrivateExponent());
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

}
