package cn.mtjsoft.lib_encryption;

import org.junit.Test;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

import cn.mtjsoft.lib_encryption.AES.AESUtil;
import cn.mtjsoft.lib_encryption.BASE64.Base64Util;
import cn.mtjsoft.lib_encryption.MD5.MD5Util;
import cn.mtjsoft.lib_encryption.RSA.RSAUtil;
import cn.mtjsoft.lib_encryption.SHA.SHAUtil;
import cn.mtjsoft.lib_encryption.SM2.SM2Util;
import cn.mtjsoft.lib_encryption.SM3.SM3Util;
import cn.mtjsoft.lib_encryption.SM4.SM4Util;
import cn.mtjsoft.lib_encryption.utils.Util;

/**
 * Example local unit test, which will execute on the development machine (host).
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
public class ExampleUnitTest {
    /**
     * AES对称加密
     */
    @Test
    public void aesTest() {
        byte[] key = AESUtil.generateKey();
        System.out.println("key: " + Util.byte2HexStr(key));
        String dataString = "我是测试aesTest明文";
        System.out.println("明文：$dataString");
        byte[] encrypt = AESUtil.encrypt(dataString.getBytes(), key);
        String encryptHexStr = Util.byte2HexStr(encrypt);
        System.out.println("AES加密: " + encryptHexStr);
        String decryptHexStr = new String(AESUtil.decrypt(encrypt, key));
        System.out.println("AES解密: " + decryptHexStr);
    }

    /**
     * BASE64编码
     */
    @Test
    public void base64Test() {
        String dataString = "我是测试base64Test明文";
        System.out.println("明文：$dataString");
        String encode = Base64Util.encode(dataString.getBytes());
        System.out.println("base64编码: " + encode);
        System.out.println("base64解码: " + new String(Base64Util.decode(encode)));
    }

    /**
     * MD5摘要
     */
    @Test
    public void md5Test() {
        String dataString = "我是测试md5Test明文";
        System.out.println("明文：" + dataString);
        System.out.println("md5摘要: " + MD5Util.stringMD5(dataString));
    }

    /**
     * SHA
     */
    @Test
    public void shaTest() {
        String dataString = "我是测试shaTest明文";
        System.out.println("明文：" + dataString);
        System.out.println("sha1摘要: " + SHAUtil.stringSHA(dataString, SHAUtil.SHA1));
        System.out.println("sha256摘要: " + SHAUtil.stringSHA(dataString, SHAUtil.SHA256));
    }

    /**
     * RSA非对称加密
     */
    @Test
    public void rsaTest() throws Exception {
        String dataString = "我是测试rsaTest明文";
        System.out.println("明文：" + dataString);
        KeyPair key = RSAUtil.generateRSAKeyPair();
        // 获取公私钥
        PrivateKey privateKey = key.getPrivate();
        PublicKey publicKey = key.getPublic();
        byte[] encryptByPublicKey = RSAUtil.encryptByPublicKey(dataString.getBytes(), publicKey);
        System.out.println("公钥加密明文：" + Util.byte2HexStr(encryptByPublicKey));
        System.out.println("私钥解密：" + new String(RSAUtil.decryptByPrivateKey(encryptByPublicKey, privateKey)));

        byte[] encryptByPrivateKey = RSAUtil.encryptByPrivateKey(dataString.getBytes(), privateKey);
        System.out.println("私钥加密明文：" + Util.byte2HexStr(encryptByPrivateKey));
        System.out.println("公钥解密：" + new String(RSAUtil.decryptByPublicKeyKey(encryptByPrivateKey, publicKey)));

        byte[] signWithSHA256 = RSAUtil.signWithSHA256(dataString.getBytes(), privateKey);
        System.out.println("私钥对明文数据SHA256签名：" + Util.byte2HexStr(signWithSHA256));
        byte[] signWithMD5 = RSAUtil.signWithMD5(dataString.getBytes(), privateKey);
        System.out.println("私钥对明文数据MD5签名：" + Util.byte2HexStr(signWithMD5));

        boolean verifySignWithSHA256 = RSAUtil.verifySignWithSHA256(dataString.getBytes(), signWithSHA256, publicKey);
        System.out.println("公钥对SHA256签名验签：" + verifySignWithSHA256);
        boolean verifySignWithMD5 = RSAUtil.verifySignWithMD5(dataString.getBytes(), signWithMD5, publicKey);
        System.out.println("公钥对MD5签名验签：" + verifySignWithMD5);
    }

    /**
     * 国产SM2非对称加密
     */
    @Test
    public void sm2Test() {
        String dataString = "我是测试sm2Test明文";
        System.out.println("明文：" + dataString);

        // 获取随机的公私钥
        byte[][] key = SM2Util.generateKeyPair();
        byte[] publicKey = key[0];
        byte[] privateKey = key[1];

        System.out.println("私钥：" + privateKey.length + "  " + Util.byte2HexStr(privateKey));
        System.out.println("公钥：" + Util.byte2HexStr(publicKey));

        byte[] encryptByPublicKey = SM2Util.encrypt(publicKey, dataString.getBytes());
        System.out.println("公钥加密明文：" + Util.byte2HexStr(encryptByPublicKey));
        System.out.println("私钥解密：" + new String(SM2Util.decrypt(privateKey, encryptByPublicKey)));

        byte[] sign = SM2Util.sign(privateKey, encryptByPublicKey);
        System.out.println("签名：" + Util.byte2HexStr(sign));
        boolean verifySign = SM2Util.verifySign(publicKey, encryptByPublicKey, sign);
        System.out.println("验签：" + verifySign);
    }

    /**
     * 国产SM3摘要
     */
    @Test
    public void sm3Test() {
        String dataString = "我是测试sm3Test明文";
        System.out.println("明文：" + dataString);
        System.out.println("sm3摘要: " + SM3Util.encryptInner(dataString));
    }

    /**
     * 国产SM4对称加密
     */
    @Test
    public void sm4Test() {
        String dataString = "我是测试sm4Test明文";
        System.out.println("明文：" + dataString);

        byte[] key = SM4Util.createSM4Key();
        System.out.println("密钥：" + Util.byte2HexStr(key));

        byte[] encryptCBC = SM4Util.encrypt(dataString.getBytes(), key, SM4Util.SM4_CBC_PKCS5, new byte[16]);
        System.out.println("CBC加密：" + Util.byte2HexStr(encryptCBC));
        System.out.println("CBC解密：" + new String(SM4Util.decrypt(encryptCBC, key, SM4Util.SM4_CBC_PKCS5, new byte[16])));

        byte[] encryptECB = SM4Util.encrypt(dataString.getBytes(), key, SM4Util.SM4_ECB_PKCS5, null);
        System.out.println("ECB加密：" + Util.byte2HexStr(encryptECB));
        System.out.println("ECB解密：" + new String(SM4Util.decrypt(encryptECB, key, SM4Util.SM4_ECB_PKCS5, null)));
    }
}