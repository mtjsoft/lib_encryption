package cn.mtjsoft.www.myencryptiondemo.rsa;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;

/**
 * @author mtj
 * @date 2021/8/6
 * @desc 非对称加密算法。
 * @email mtjsoft3@gmail.com
 */
public class RSAUtil {
    private static final String RSA = "RSA";

    private static final String RSA_NO_PADDING = "RSA/ECB/NoPadding";

    private static final String RSA_PADDING = "RSA/ECB/PKCS1Padding";

    // 密钥长度
    private static final int DEFAULT_KEY_SIZE = 2048;

    // 当前秘钥支持加密的最大字节数
    // 待加密的字节数不能超过密钥的长度值除以 8 再减去 11（即：KeySize / 8 - 11），而加密后得到密文的字节数，正好是密钥的长度值除以 8（即：KeySize / 8）
    private static final int DEFAULT_BUFFERSIZE = (DEFAULT_KEY_SIZE / 8) - 11;

    /**
     * 随机生成RSA密钥对
     *
     * 密钥长度，范围：512～2048
     * 一般1024 或 2048
     */
    public static KeyPair generateRSAKeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(RSA);
            kpg.initialize(DEFAULT_KEY_SIZE);
            return kpg.genKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 用公钥进行加密
     *
     * @param data 原文
     */
    public static byte[] encryptByPublicKey(byte[] data, PublicKey publicKey) {
        // 加密数据
        try {
            Cipher cipher = Cipher.getInstance(RSA_PADDING);
            // 编码前设定编码方式及密钥
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            // 传入编码数据并返回编码结果
            return cipher.doFinal(data);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 用私钥进行加密
     *
     * @param data 原文
     */
    public static byte[] encryptByPrivateKey(byte[] data, PrivateKey privateKey) {
        // 加密数据
        try {
            Cipher cipher = Cipher.getInstance(RSA_PADDING);
            // 编码前设定编码方式及密钥
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            // 传入编码数据并返回编码结果
            return cipher.doFinal(data);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 用公钥解密
     *
     * @param encryptedData 经过加密数据
     * @param publicKey     公钥
     */
    public static byte[] decryptByPrivateKey(byte[] encryptedData, PublicKey publicKey) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_PADDING);
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            return cipher.doFinal(encryptedData);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 用私钥解密
     *
     * @param encryptedData 经过加密数据
     * @param privateKey    私钥
     */
    public static byte[] decryptByPrivateKey(byte[] encryptedData, PrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_PADDING);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(encryptedData);
        } catch (Exception e) {
            return null;
        }
    }
}
