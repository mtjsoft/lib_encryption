package cn.mtjsoft.www.myencryptiondemo.utils;

import android.text.TextUtils;

import java.util.Locale;
import java.util.Random;

/**
 * @author mtj
 * @date 2021/8/6
 * @desc
 * @email mtjsoft3@gmail.com
 */
public class Util {
    /**
     * 十六进制字符串转换为byte[]
     *
     * @param hexStr 需要转换为byte[]的字符串
     * @return 转换后的byte[]
     */
    public static byte[] hexStr2Bytes(String hexStr) {
        if (TextUtils.isEmpty(hexStr)) {
            return null;
        }
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
    public static String byte2HexStr(byte[] bytes) {
        if (bytes == null) {
            return "";
        }
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

    /**
     * 随机生成一个指定长度的字节数组
     *
     * @param len 给定的长度
     */
    public static byte[] genRandomBytes(int len) {
        byte[] seed = new byte[len];
        Random random = new Random();
        random.nextBytes(seed);
        return seed;
    }


    /**
     * pkcs7填充
     * source : 源数据
     * blocksize : 要填充的倍数
     */
    public static byte[] pkcs7_pad(byte[] source, int blocksize) {
        int sourceLength = source.length;
        int padDataLen = blocksize - (sourceLength % blocksize);
        int afterPadLen = sourceLength + padDataLen;
        byte[] paddingResult = new byte[afterPadLen];
        System.arraycopy(source, 0, paddingResult, 0, sourceLength);
        for (int i = sourceLength; i < afterPadLen; i++) {
            paddingResult[i] = (byte) padDataLen;
        }
        return paddingResult;
    }

    /**
     * pkcs7 截取
     *
     * @throws Exception
     */
    public static byte[] pkcs7_unpad(byte[] data) throws Exception {
        int lastValue = data[data.length - 1];
        byte[] unpad = new byte[data.length - lastValue];
        System.arraycopy(data, 0, unpad, 0, unpad.length);
        return unpad;
    }
}
