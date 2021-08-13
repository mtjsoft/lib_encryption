package cn.mtjsoft.lib_encryption.AES;

import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author mtj
 * @date 2021/8/6
 * @desc 对称加密，加解密的密钥需要保持一致
 * @email mtjsoft3@gmail.com
 */
public class AESUtil {
    /**
     * 算法/模式/填充                16字节加密后数据长度        不满16字节加密后长度
     * AES/CBC/NoPadding             16                          不支持
     * AES/CBC/PKCS5Padding          32                          16
     * AES/CBC/ISO10126Padding       32                          16
     * AES/CFB/NoPadding             16                          原始数据长度
     * AES/CFB/PKCS5Padding          32                          16
     * AES/CFB/ISO10126Padding       32                          16
     * AES/ECB/NoPadding             16                          不支持
     * AES/ECB/PKCS5Padding          32                          16
     * AES/ECB/ISO10126Padding       32                          16
     * AES/OFB/NoPadding             16                          原始数据长度
     * AES/OFB/PKCS5Padding          32                          16
     * AES/OFB/ISO10126Padding       32                          16
     * AES/PCBC/NoPadding            16                          不支持
     * AES/PCBC/PKCS5Padding         32                          16
     * AES/PCBC/ISO10126Padding      32                          16
     */
    private static final String AES = "AES";

    private static final String AES_ECB_NO_PADDING = "AES/ECB/NoPadding";

    private static final String AES_CBC_NO_PADDING = "AES/CBC/NoPadding";

    private static final String AES_CBC_PKCS5 = "AES/CBC/PKCS5Padding";

    /**
     * 生成秘钥
     */
    public static byte[] generateKey() {
        KeyGenerator keyGen = null;
        try {
            // 秘钥生成器
            keyGen = KeyGenerator.getInstance(AES);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        if (keyGen != null) {
            // 初始秘钥生成器
            keyGen.init(128);
            // 生成秘钥
            SecretKey secretKey = keyGen.generateKey();
            // 获取秘钥字节数组
            return secretKey.getEncoded();
        }
        return null;
    }

    /**
     * 生成秘钥
     */
    public static byte[] generateKey256() {
        KeyGenerator keyGen = null;
        try {
            // 秘钥生成器
            keyGen = KeyGenerator.getInstance(AES);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        if (keyGen != null) {
            // 初始秘钥生成器
            keyGen.init(256);
            // 生成秘钥
            SecretKey secretKey = keyGen.generateKey();
            // 获取秘钥字节数组
            return secretKey.getEncoded();
        }
        return null;
    }

    /**
     * 加密
     */
    public static byte[] encrypt(byte[] data, byte[] key) {
        return init(data, key, Cipher.ENCRYPT_MODE);
    }

    /**
     * 解密
     */
    public static byte[] decrypt(byte[] data, byte[] key) {
        return init(data, key, Cipher.DECRYPT_MODE);
    }

    private static byte[] init(byte[] data, byte[] key, int decryptMode) {
        try {
            // 恢复秘钥
            SecretKey secretKey = new SecretKeySpec(key, AES);
            // 对Cipher初始化,加密模式
            Cipher cipher = Cipher.getInstance(AES_CBC_PKCS5);
            //CBC模式
            // 对Cipher初始化,加密模式
            cipher.init(decryptMode, secretKey, new IvParameterSpec(new byte[cipher.getBlockSize()]));
            // 解密数据
            return cipher.doFinal(data);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
