package cn.mtjsoft.lib_encryption.utils;

import android.text.TextUtils;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Locale;

import static java.lang.System.arraycopy;

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
        SecureRandom random = new SecureRandom();
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

    /*
     * 将两个byte数组拼接成一个byte数组
     */
    public static byte[] pinJie2(byte[] a, byte[] b) {
        byte[] bytes = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, bytes, a.length, b.length);
        return bytes;
    }

    /*
     * 将三个byte数组拼接成一个byte数组
     */
    public static byte[] pinJie3(byte[] a, byte[] b, byte[] c) {
        byte[] data = new byte[a.length + b.length + c.length];
        arraycopy(a, 0, data, 0, a.length);
        arraycopy(b, 0, data, a.length, b.length);
        arraycopy(c, 0, data, a.length + b.length, c.length);
        return data;
    }

    /**
     * 变长拼接
     *
     * @param bytes 数据源
     * @return 结果
     */
    public static byte[] pinJie(byte[]... bytes) {
        int length = 0;
        for (byte[] temp : bytes) {
            length += temp.length;
        }
        byte[] totalData = new byte[length];
        int tempLength = 0;
        for (byte[] temp : bytes) {
            // Object src,  int  srcPos, Object dest , int destPos, int length
            arraycopy(temp, 0, totalData, tempLength, temp.length);
            tempLength += temp.length;
        }
        return totalData;
    }

    /**
     * 把一个整形int转换成byte数组 低位再前高位在后
     */
    public static byte[] intToByte4(int i) {
        byte[] targets = new byte[4];
        targets[3] = (byte) (i & 0xFF);
        targets[2] = (byte) (i >> 8 & 0xFF);
        targets[1] = (byte) (i >> 16 & 0xFF);
        targets[0] = (byte) (i >> 24 & 0xFF);
        return targets;
    }

    /**
     * 把一个byte数组转换成 整形int
     */
    public static int byte4ToInt(byte[] bytes) {
        int b0 = bytes[0] & 0xFF;
        int b1 = bytes[1] & 0xFF;
        int b2 = bytes[2] & 0xFF;
        int b3 = bytes[3] & 0xFF;
        return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
    }

    /*
     * 截取byte数组 count - 截取的长度
     */
    public static byte[] subBytes(byte[] src, int begin, int count) {
        byte[] bs = new byte[count];
        System.arraycopy(src, begin, bs, 0, count);
        return bs;
    }

    /*
     * 截取byte数组 count - 末尾下标
     */
    public static byte[] subBytes1(byte[] src, int begin, int count) {
        byte[] bs = new byte[count - begin];
        System.arraycopy(src, begin, bs, 0, count - begin);
        return bs;
    }

    /**
     * 填充128字节
     */
    public static byte[] zerofill128(byte[] bt) {
        byte[] bytes = new byte[128];
        Arrays.fill(bytes, 0, 112, (byte) 0x00);
        System.arraycopy(bt, 0, bytes, 112, 16);
        return bytes;
    }
}
