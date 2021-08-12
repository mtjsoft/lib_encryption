package cn.mtjsoft.www.myencryptiondemo

import cn.mtjsoft.www.myencryptiondemo.AES.AESUtil
import cn.mtjsoft.www.myencryptiondemo.BASE64.Base64Util
import cn.mtjsoft.www.myencryptiondemo.MD5.MD5Util
import cn.mtjsoft.www.myencryptiondemo.RSA.RSAUtil
import cn.mtjsoft.www.myencryptiondemo.SHA.SHAUtil
import cn.mtjsoft.www.myencryptiondemo.SM3.SM3Util
import cn.mtjsoft.www.myencryptiondemo.SM4.SM4Util
import cn.mtjsoft.www.myencryptiondemo.utils.Util
import org.junit.Test

/**
 * Example local unit test, which will execute on the development machine (host).
 *
 * See [testing documentation](http://d.android.com/tools/testing).
 */
class ExampleUnitTest {

    /**
     * AES对称加密
     */
    @Test
    fun aesTest() {
        val key = AESUtil.generateKey()
        println("key: ${Util.byte2HexStr(key)}")
        val dataString = "我是测试aesTest明文"
        println("明文：$dataString")
        val encrypt = AESUtil.encrypt(dataString.toByteArray(), key)
        val encryptHexStr = Util.byte2HexStr(encrypt)
        println("AES加密: $encryptHexStr")
        val decryptHexStr = String(AESUtil.decrypt(encrypt, key))
        println("AES解密: $decryptHexStr")
    }

    /**
     * BASE64编码
     */
    @Test
    fun base64Test() {
        val dataString = "我是测试base64Test明文"
        println("明文：$dataString")
        val encode = Base64Util.encode(dataString.toByteArray())
        println("base64编码: $encode")
        println("base64解码: ${String(Base64Util.decode(encode))}")
    }

    /**
     * MD5摘要
     */
    @Test
    fun md5Test() {
        val dataString = "我是测试md5Test明文"
        println("明文：$dataString")
        println("md5摘要: ${MD5Util.stringMD5(dataString)}")
    }

    /**
     * SHA
     */
    @Test
    fun shaTest() {
        val dataString = "我是测试shaTest明文"
        println("明文：$dataString")
        println("sha1摘要: ${SHAUtil.stringSHA(dataString, SHAUtil.SHA1)}")
        println("sha256摘要: ${SHAUtil.stringSHA(dataString, SHAUtil.SHA256)}")
    }

    /**
     * RSA非对称加密
     */
    @Test
    fun rsaTest() {
        val dataString = "我是测试rsaTest明文"
        println("明文：$dataString")
        val key = RSAUtil.generateRSAKeyPair()
        val privateKey = key.private
        val publicKey = key.public
        val encryptByPublicKey = RSAUtil.encryptByPublicKey(dataString.toByteArray(), publicKey)
        println("公钥加密明文：" + Util.byte2HexStr(encryptByPublicKey))
        println("私钥解密：" + String(RSAUtil.decryptByPrivateKey(encryptByPublicKey, privateKey)))

        val encryptByPrivateKey = RSAUtil.encryptByPrivateKey(dataString.toByteArray(), privateKey)
        println("私钥加密明文：" + Util.byte2HexStr(encryptByPrivateKey))
        println("公钥解密：" + String(RSAUtil.decryptByPublicKeyKey(encryptByPrivateKey, publicKey)))

        val signWithSHA256 = RSAUtil.signWithSHA256(dataString.toByteArray(), privateKey)
        println("私钥对明文数据SHA256签名：" + Util.byte2HexStr(signWithSHA256))
        val signWithMD5 = RSAUtil.signWithMD5(dataString.toByteArray(), privateKey)
        println("私钥对明文数据MD5签名：" + Util.byte2HexStr(signWithMD5))

        val verifySignWithSHA256 = RSAUtil.verifySignWithSHA256(dataString.toByteArray(), signWithSHA256, publicKey)
        println("公钥对SHA256签名验签：$verifySignWithSHA256")
        val verifySignWithMD5 = RSAUtil.verifySignWithMD5(dataString.toByteArray(), signWithMD5, publicKey)
        println("公钥对MD5签名验签：$verifySignWithMD5")
    }

    /**
     * 国产SM2非对称加密
     */
    @Test
    fun sm2Test() {
        val dataString = "我是测试sm2Test明文"
        println("明文：$dataString")
    }

    /**
     * 国产SM3摘要
     */
    @Test
    fun sm3Test() {
        val dataString = "我是测试sm3Test明文"
        println("明文：$dataString")
        println("sm3摘要: ${SM3Util.encryptInner(dataString)}")
    }

    /**
     * 国产SM4对称加密
     */
    @Test
    fun sm4Test() {
        val dataString = "我是测试sm4Test明文"
        println("明文：$dataString")

        val key = SM4Util.createSM4Key()
        println("密钥：" + Util.byte2HexStr(key))

        val encryptCBC = SM4Util.encryptCBC(dataString.toByteArray(), key)
        println("CBC加密：${Util.byte2HexStr(encryptCBC)}")
        println("CBC解密：${String(SM4Util.decryptCBC(encryptCBC, key))}")

        val encryptECB = SM4Util.encryptECB(dataString.toByteArray(), key)
        println("ECB加密：${Util.byte2HexStr(encryptECB)}")
        println("ECB解密：${String(SM4Util.decryptECB(encryptECB, key))}")
    }
}