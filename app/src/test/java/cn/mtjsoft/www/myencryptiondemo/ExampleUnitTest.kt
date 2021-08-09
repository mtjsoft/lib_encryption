package cn.mtjsoft.www.myencryptiondemo

import cn.mtjsoft.www.myencryptiondemo.aes.AesUtil
import cn.mtjsoft.www.myencryptiondemo.base64.Base64Util
import cn.mtjsoft.www.myencryptiondemo.md5.MD5Util
import cn.mtjsoft.www.myencryptiondemo.rsa.RSAUtil
import cn.mtjsoft.www.myencryptiondemo.sha.SHAUtil
import cn.mtjsoft.www.myencryptiondemo.utils.Util
import org.junit.Test

/**
 * Example local unit test, which will execute on the development machine (host).
 *
 * See [testing documentation](http://d.android.com/tools/testing).
 */
class ExampleUnitTest {

    @Test
    fun aesTest() {
        val key = AesUtil.generateKey()
        println("key: ${Util.byte2HexStr(key)}")
        val dataString = "我是测试aesTest明文"
        println("明文：$dataString")
        val encrypt = AesUtil.encrypt(dataString.toByteArray(), key)
        val encryptHexStr = Util.byte2HexStr(encrypt)
        println("AES加密: $encryptHexStr")
        val decryptHexStr = String(AesUtil.decrypt(encrypt, key))
        println("AES解密: $decryptHexStr")
    }

    @Test
    fun base64Test() {
        val dataString = "我是测试base64Test明文"
        println("明文：$dataString")
        val encode = Base64Util.encode(dataString.toByteArray())
        println("base64编码: $encode")
        println("base64解码: ${String(Base64Util.decode(encode))}")
    }

    @Test
    fun md5Test() {
        val dataString = "我是测试md5Test明文"
        println("明文：$dataString")
        println("md5摘要: ${MD5Util.stringMD5(dataString)}")
    }

    @Test
    fun shaTest() {
        val dataString = "我是测试shaTest明文"
        println("明文：$dataString")
        println("sha1摘要: ${SHAUtil.stringSHA(dataString, SHAUtil.SHA1)}")
        println("sha256摘要: ${SHAUtil.stringSHA(dataString, SHAUtil.SHA256)}")
    }

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
}