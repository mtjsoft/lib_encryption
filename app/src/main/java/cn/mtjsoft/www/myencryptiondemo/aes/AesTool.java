package cn.mtjsoft.www.myencryptiondemo.aes;

import java.util.Locale;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AesTool {

    private static final String AES = "AES"; //AES 加密
    private static final String ALGORITHM = "AES/CBC/PKCS5Padding"; //algorithm/mode/padding
    //密码 16 或 32 位
    private static final String key = "D0ORAjnrCkQfopvoKBEwvfYVowHTfTuE";
    //iv偏移量 16 位
    private static final String iv = "h0z7SCrmnAhvpCLq";

    public static void main(String[] args) throws Exception {
        String temp = "我是明文数据";
        System.out.println("原始数据:" + temp);
        String passwordEnc = AesTool.encrypt(temp);//进行java的AES/CBC/NoPadding加密
        System.out.println("加密之后的字符串:" + passwordEnc);
        String passwordDec = AesTool.decrypt(passwordEnc);//解密
        System.out.println("解密后的数据:" + passwordDec);
    }

    /**
     * 加密：对字符串进行加密，并返回字符串
     *
     * @param encryptStr 需要加密的字符串
     * @return 加密后的字符串
     */
    public static String encrypt(String encryptStr) {
        try {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), AES);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivParameterSpec);
            byte[] encrypted = cipher.doFinal(encryptStr.getBytes());
            return byte2HexStr(encrypted);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return encryptStr;
    }

    /**
     * 解密：对加密后的十六进制字符串(hex)进行解密，并返回字符串
     *
     * @param encryptedStr 需要解密的，加密后的十六进制字符串
     * @return 解密后的字符串
     */
    public static String decrypt(String encryptedStr) {
        try {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), AES);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivParameterSpec);
            byte[] bytes = hexStr2Bytes(encryptedStr);
            byte[] original = cipher.doFinal(bytes);
            return new String(original);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return encryptedStr;
    }

    /**
     * 十六进制字符串转换为byte[]
     *
     * @param hexStr 需要转换为byte[]的字符串
     * @return 转换后的byte[]
     */
    private static byte[] hexStr2Bytes(String hexStr) {
        /*对输入值进行规范化整理*/
        hexStr = hexStr.trim().replace(" ", "").toUpperCase(Locale.US);
        //处理值初始化
        int m = 0, n = 0;
        int iLen = hexStr.length() / 2; //计算长度
        byte[] ret = new byte[iLen]; //分配存储空间

        for (int i = 0; i < iLen; i++) {
            m = i * 2 + 1;
            n = m + 1;
            ret[i] = (byte) (Integer.decode("0x" + hexStr.substring(i * 2, m) + hexStr.substring(m, n)) & 0xFF);
        }
        return ret;
    }


    /**
     * byte[]转换为十六进制字符串
     *
     * @param bytes 需要转换为字符串的byte[]
     * @return 转换后的十六进制字符串
     */
    private static String byte2HexStr(byte[] bytes) {
        StringBuilder hs = new StringBuilder();
        String stmp = "";
        for (byte aByte : bytes) {
            stmp = (Integer.toHexString(aByte & 0XFF));
            if (stmp.length() == 1) {
                hs.append("0");
                hs.append(stmp);
            } else {
                hs.append(stmp);
            }
        }
        return hs.toString().toUpperCase();
    }

}
