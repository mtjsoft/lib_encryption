package cn.mtjsoft.www.myencryptiondemo.SM4;

import java.security.SecureRandom;

/**
 * @author mtj
 * @date 2021/8/12
 * @desc 国产对称加密算法
 * @email mtjsoft3@gmail.com
 *
 * 国产加密算法可有效规避老外的RSA算法等存在的脆弱性和“预置后门”的安全风险
 * 另一方面确保密码算法这一关键环节的自主可控
 *
 * SM4分组密码算法是我国自主设计的分组对称密码算法
 */
public class SM4Util {
    /* 使用CBC模式，需要一个向量iv，可增加加密算法的强度 */
    private static final String PARAMETER_SPEC = "1234567890123456";

    private static final boolean isPadding = true;

    /**
     * ECB 模式，加密
     *
     * @param cipherBytes 原始数据
     * @param keyBytes    秘钥，长度 = 16
     * @return 加密后的数据，Base64处理过的，可能为null
     */
    public static byte[] encryptECB(byte[] cipherBytes, byte[] keyBytes) {
        return encryptECBInner(cipherBytes, keyBytes);
    }

    /**
     * ECB 模式，解密
     *
     * @param cipherBytes 加密的数据
     * @param keyBytes    秘钥，长度 = 16
     * @return 解密后的数据，可能为null
     */
    public static byte[] decryptECB(byte[] cipherBytes, byte[] keyBytes) {
        return decryptECBInner(cipherBytes, keyBytes);
    }

    /**
     * CBC 模式，加密
     *
     * @param cipherBytes 原始数据
     * @param keyBytes    秘钥，长度 = 16
     * @return 加密后的数据
     */
    public static byte[] encryptCBC(byte[] cipherBytes, byte[] keyBytes) {
        return encryptCBCInner(cipherBytes, keyBytes, new byte[16]);
    }

    /**
     * CBC 模式，解密
     *
     * @param cipherBytes 加密的数据
     * @param keyBytes    秘钥，长度 = 16
     * @return 解密后的数据，可能为null
     */
    public static byte[] decryptCBC(byte[] cipherBytes, byte[] keyBytes) {
        return decryptCBCInner(cipherBytes, keyBytes, new byte[16]);
    }

    /**
     * 随机生成一个 SM4 秘钥
     *
     * @return 字符流，长度为16
     */
    public static byte[] createSM4Key() {
        return createSM4KeyInner();
    }

    /* ------------------------ 内部实现 ----------------------- */

    /**
     * 随机生成一个 SM4 秘钥
     *
     * @return byte数组，长度为16
     */
    private static byte[] createSM4KeyInner() {
        byte[] keyBytes = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(keyBytes);
        return keyBytes;
    }

    /**
     * CBC 模式，加密
     *
     * @param srcBytes 原始数据
     * @param keyBytes 秘钥，长度 = 16
     * @param ivBytes  偏移量，长度 = 16
     * @return 加密后的数据
     */
    private static byte[] encryptCBCInner(byte[] srcBytes, byte[] keyBytes, byte[] ivBytes) {
        try {
            SM4 sm4 = new SM4();
            long[] secretKey = sm4.sm4_setkey_enc(keyBytes);
            return sm4.sm4_crypt_cbc(SM4.SM4_ENCRYPT, secretKey, isPadding, ivBytes, srcBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * CBC 模式，解密
     *
     * @param encryptedBytes 加密后的数据
     * @param keyBytes       秘钥，长度 = 16
     * @param ivBytes        偏移量，长度 = 16
     * @return 解密后的数据
     */
    private static byte[] decryptCBCInner(byte[] encryptedBytes, byte[] keyBytes, byte[] ivBytes) {
        try {
            SM4 sm4 = new SM4();
            long[] secretKey = sm4.sm4_setkey_dec(keyBytes);
            return sm4.sm4_crypt_cbc(SM4.SM4_DECRYPT, secretKey, isPadding, ivBytes, encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * ECB 模式，加密
     *
     * @param srcBytes 原始数据
     * @param keyBytes 秘钥，长度 = 16
     * @return 加密后的数据
     */
    private static byte[] encryptECBInner(byte[] srcBytes, byte[] keyBytes) {
        try {
            SM4 sm4 = new SM4();
            long[] secretKey = sm4.sm4_setkey_enc(keyBytes);
            return sm4.sm4_crypt_ecb(SM4.SM4_ENCRYPT, secretKey, isPadding, srcBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * ECB 模式，解密
     *
     * @param encryptBytes 加密后的数据
     * @param keyBytes     秘钥，长度 = 16
     * @return 解密后的数据
     */
    private static byte[] decryptECBInner(byte[] encryptBytes, byte[] keyBytes) {
        try {
            SM4 sm4 = new SM4();
            long[] secretKey = sm4.sm4_setkey_dec(keyBytes);
            return sm4.sm4_crypt_ecb(SM4.SM4_DECRYPT, secretKey, isPadding, encryptBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
