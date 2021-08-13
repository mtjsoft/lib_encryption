package cn.mtjsoft.lib_encryption.RSA;

import java.io.ByteArrayOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

/**
 * @author mtj
 * @date 2021/8/6
 * @desc 非对称加密算法。
 *
 * 加密：防止消息泄露
 * 签名：防止消息篡改
 * （总结：公钥加密、私钥解密、私钥签名、公钥验签）
 * @email mtjsoft3@gmail.com
 */
public class RSAUtil {
    private static final String RSA = "RSA";

    /**
     * 填充方式
     */
    private static final String RSA_NO_PADDING = "RSA/ECB/NoPadding";

    private static final String RSA_PADDING = "RSA/ECB/PKCS1Padding";

    /**
     * 签名方式
     */
    private static final String SIGN_MD5withRSA = "MD5withRSA";

    private static final String SIGN_SHA256WithRSA = "SHA256WithRSA";

    /**
     * 密钥长度
     */
    private static final int DEFAULT_KEY_SIZE = 2048;

    /**
     * 待解密的字节数不能超过密钥的长度值除以 8 （即：KeySize / 8 ）
     */
    private static final int MAX_DECRYPT_BLOCK = DEFAULT_KEY_SIZE / 8;

    /**
     * 待加密的字节数不能超过密钥的长度值除以 8 再减去 11（即：KeySize / 8 - 11）
     */
    private static final int MAX_ENCRYPT_BLOCK = MAX_DECRYPT_BLOCK - 11;

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
     * 通过公钥byte[](publicKey.getEncoded())将公钥还原，适用于RSA算法
     *
     * @param publicKeys 公钥byte[]，(publicKey.getEncoded())
     */
    public static PublicKey getPublicKey(byte[] publicKeys) {
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeys);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA);
            return keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 通过私钥byte[]将私钥还原，适用于RSA算法
     *
     * @param privateKeys 私钥byte[]，(privateKey.getEncoded())
     */
    public static PrivateKey getPrivateKey(byte[] privateKeys) {
        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeys);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA);
            return keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
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
            return segmented(data, cipher, true);
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
            return segmented(data, cipher, true);
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
    public static byte[] decryptByPublicKeyKey(byte[] encryptedData, PublicKey publicKey) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_PADDING);
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            return segmented(encryptedData, cipher, false);
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
            return segmented(encryptedData, cipher, false);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * SHA256
     * 用私钥签名
     *
     * @param bytes      待签名数据
     * @param privateKey 私钥
     * @return 结果
     */
    public static byte[] signWithSHA256(byte[] bytes, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance(SIGN_SHA256WithRSA);
        signature.initSign(privateKey);
        signature.update(bytes);
        return signature.sign();
    }

    /**
     * SHA256
     * 用公钥验签
     *
     * @param srcData   原始数据
     * @param signBytes 签名数据
     * @param publicKey 公钥
     * @return 结果
     */
    public static boolean verifySignWithSHA256(byte[] srcData, byte[] signBytes, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance(SIGN_SHA256WithRSA);
        signature.initVerify(publicKey);
        signature.update(srcData);
        return signature.verify(signBytes);
    }

    /**
     * MD5
     * 用私钥签名
     *
     * @param bytes      待签名数据
     * @param privateKey 私钥
     * @return 结果
     */
    public static byte[] signWithMD5(byte[] bytes, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance(SIGN_MD5withRSA);
        signature.initSign(privateKey);
        signature.update(bytes);
        return signature.sign();
    }

    /**
     * MD5
     * 用公钥验签
     *
     * @param srcData   原始数据
     * @param signBytes 签名数据
     * @param publicKey 公钥
     * @return 结果
     */
    public static boolean verifySignWithMD5(byte[] srcData, byte[] signBytes, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance(SIGN_MD5withRSA);
        signature.initVerify(publicKey);
        signature.update(srcData);
        return signature.verify(signBytes);
    }

    /**
     * 分段加解密
     *
     * @param data      待加解密的数据
     * @param isEncrypt 是否是加密，否则是解密
     */
    private static byte[] segmented(byte[] data, Cipher cipher, boolean isEncrypt) throws Exception {
        int inputLen = data.length;
        // 不够分段加密条件，直接进行一次性加密返回
        if (isEncrypt && inputLen <= MAX_ENCRYPT_BLOCK) {
            return cipher.doFinal(data);
        }
        // 不够分段解密条件，直接进行一次性解密返回
        if (!isEncrypt && inputLen <= MAX_DECRYPT_BLOCK) {
            return cipher.doFinal(data);
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offset = 0;
        byte[] cache;
        int i = 0;
        int maxLen = isEncrypt ? MAX_ENCRYPT_BLOCK : MAX_DECRYPT_BLOCK;
        // 对数据分段加密
        while (inputLen - offset > 0) {
            if (inputLen - offset > maxLen) {
                cache = cipher.doFinal(data, offset, maxLen);
            } else {
                cache = cipher.doFinal(data, offset, inputLen - offset);
            }
            out.write(cache, 0, cache.length);
            i++;
            offset = i * maxLen;
        }
        out.close();
        return out.toByteArray();
    }
}
