package cn.mtjsoft.lib_encryption.SM3;

import org.bouncycastle.crypto.digests.SM3Digest;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;

import cn.mtjsoft.lib_encryption.utils.Util;

/**
 * @author mtj
 * @date 2021/8/12
 * @desc 国产摘要算法
 * @email mtjsoft3@gmail.com
 *
 * 国产加密算法可有效规避老外的RSA算法等存在的脆弱性和“预置后门”的安全风险
 * 另一方面确保密码算法这一关键环节的自主可控
 *
 * SM3摘要算法是我国自主设计的密码摘要算法，安全性要高于MD5算法（128位）和SHA-1算法（160位），SM3算法的压缩函数与SHA-256具有相似结构，但设计更加复杂
 */
public class SM3Util {
    /**
     * SM3 加密
     *
     * @param source 原始数组
     * @return 加密后的，32位数组
     */
    public static byte[] encryptInner(byte[] source) {
        byte[] result = new byte[32];
        SM3Digest sm3 = new SM3Digest();
        sm3.update(source, 0, source.length);
        sm3.doFinal(result, 0);
        return result;
    }

    public static String encryptInner(String input) {
        SM3Digest digest = new SM3Digest();
        byte[] sourceBytes = input.getBytes();
        digest.update(sourceBytes, 0, sourceBytes.length);
        byte[] result = new byte[32];
        digest.doFinal(result, 0);
        return Util.byte2HexStr(result);
    }

    /**
     * 计算文件摘要
     */
    public static String getMd5ByFile(File file) {
        String result = "";
        if (!file.isFile()) {
            return result;
        }
        SM3Digest digest = null;
        FileInputStream in = null;
        byte[] buffer = new byte[1024];
        int len;
        try {
            digest = new SM3Digest();
            in = new FileInputStream(file);
            while ((len = in.read(buffer, 0, 1024)) != -1) {
                digest.update(buffer, 0, len);
            }
            in.close();
            byte[] bytes = new byte[32];
            digest.doFinal(bytes, 0);
            result = Util.byte2HexStr(bytes);
        } catch (Exception e) {
            e.printStackTrace();
            result = "";
        }
        return result;
    }

    /**
     * 计算文件摘要
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
            result = Util.byte2HexStr(encryptInner(byteBuffer.array()));
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
