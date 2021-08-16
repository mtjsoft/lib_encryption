package cn.mtjsoft.lib_encryption.MD5;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import cn.mtjsoft.lib_encryption.utils.Util;

/**
 * @author mtj
 * @date 2021/8/6
 * @desc 消息摘要算法5, 单向加密算法，是不可逆的一种的加密方式
 * @email mtjsoft3@gmail.com
 *
 * MD5加密有哪些特点:
 *
 * 压缩性：任意长度的数据，算出的MD5值长度都是固定的。
 *
 * 容易计算：从原数据计算出MD5值很容易。
 *
 * 抗修改性：对原数据进行任何改动，哪怕只修改1个字节，所得到的MD5值都有很大区别。
 *
 * 强抗碰撞：已知原数据和其MD5值，想找到一个具有相同MD5值的数据（即伪造数据）是非常困难的。
 *
 * MD5应用场景：
 *
 * 一致性验证
 *
 * 数字签名
 *
 * 安全访问认证
 */
public class MD5Util {
    /**
     * 计算字符串MD5值
     */
    public static String stringMD5(String input) {
        try {
            // 拿到一个MD5转换器（如果想要SHA1参数换成”SHA1”）
            MessageDigest messageDigest = MessageDigest.getInstance("MD5");
            // 输入的字符串转换成字节数组
            byte[] inputByteArray = input.getBytes();
            // inputByteArray是输入字符串转换得到的字节数组
            messageDigest.update(inputByteArray);
            // 转换并返回结果，也是字节数组，包含16个元素
            byte[] resultByteArray = messageDigest.digest();
            // 字符数组转换成字符串返回
            return Util.byte2HexStr(resultByteArray);
        } catch (NoSuchAlgorithmException e) {
            return "";
        }
    }

    public static String stringMD5(byte[] inputByteArray) {
        try {
            // 拿到一个MD5转换器（如果想要SHA1参数换成”SHA1”）
            MessageDigest messageDigest = MessageDigest.getInstance("MD5");
            // inputByteArray是输入字符串转换得到的字节数组
            messageDigest.update(inputByteArray);
            // 转换并返回结果，也是字节数组，包含16个元素
            byte[] resultByteArray = messageDigest.digest();
            // 字符数组转换成字符串返回
            return Util.byte2HexStr(resultByteArray);
        } catch (NoSuchAlgorithmException e) {
            return "";
        }
    }

    /**
     * 计算文件MD5值
     */
    public static String getMd5ByFile(File file) {
        String result = "";
        if (!file.isFile()) {
            return result;
        }
        MessageDigest digest = null;
        FileInputStream in = null;
        byte[] buffer = new byte[1024];
        int len;
        try {
            digest = MessageDigest.getInstance("MD5");
            in = new FileInputStream(file);
            while ((len = in.read(buffer, 0, 1024)) != -1) {
                digest.update(buffer, 0, len);
            }
            in.close();
            result = Util.byte2HexStr(digest.digest());
        } catch (Exception e) {
            e.printStackTrace();
            result = "";
        }
        return result;
    }

    /**
     * 计算文件MD5值
     *
     * 采用nio的方式
     */
    public static String getMd5ByFileNio(File file) {
        String result = "";
        if (!file.isFile()) {
            return result;
        }
        FileInputStream in = null;
        try {
            in = new FileInputStream(file);
            MappedByteBuffer byteBuffer = in.getChannel().map(FileChannel.MapMode.READ_ONLY, 0, file.length());
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            md5.update(byteBuffer);
            result = Util.byte2HexStr(md5.digest());
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (null != in) {
                try {
                    in.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return result;
    }
}
