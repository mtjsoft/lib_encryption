package cn.mtjsoft.lib_encryption.SHA;

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
 * @desc
 * @email mtjsoft3@gmail.com
 *
 * SHA加密优点:
 *
 * 由于SHA也是有MD4演变过来的，所以其优点与MD5大致一样
 *
 * 压缩性：任意长度的数据，算出的SHA值长度都是固定的。
 *
 * 容易计算：从原数据计算出SHA值很容易。
 *
 * 抗修改性：对原数据进行任何改动，哪怕只修改1个字节，所得到的SHA值都有很大区别。
 *
 * 强抗碰撞：已知原数据和其SHA值，想找到一个具有相同SHA值的数据（即伪造数据）是非常困难的。
 *
 * SHA应用场景:
 *
 * 一致性验证
 *
 * 数字签名
 *
 * 安全访问认证
 */
public class SHAUtil {

    public static final String SHA1 = "SHA-1";

    public static final String SHA256 = "SHA-256";

    /**
     * 计算字符串SHA1值
     */
    public static String stringSHA(String input, String shaType) {
        try {
            // 拿到一个SHA1
            MessageDigest messageDigest = MessageDigest.getInstance(shaType);
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

    public static String stringSHA(byte[] inputByteArray, String shaType) {
        try {
            // 拿到一个SHA1
            MessageDigest messageDigest = MessageDigest.getInstance(shaType);
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
     * 计算文件SHA1值
     */
    public static String getSHAByFile(File file, String shaType) {
        String result = "";
        if (!file.isFile()) {
            return result;
        }
        MessageDigest digest = null;
        FileInputStream in = null;
        byte[] buffer = new byte[1024];
        int len;
        try {
            digest = MessageDigest.getInstance(shaType);
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
     * 计算文件SHA1值
     *
     * 采用nio的方式
     */
    public static String getSHAByFileNio(File file, String shaType) {
        String result = "";
        if (!file.isFile()) {
            return result;
        }
        FileInputStream in = null;
        try {
            in = new FileInputStream(file);
            MappedByteBuffer byteBuffer = in.getChannel().map(FileChannel.MapMode.READ_ONLY, 0, file.length());
            MessageDigest md5 = MessageDigest.getInstance(shaType);
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
