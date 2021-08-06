package cn.mtjsoft.www.myencryptiondemo

import cn.mtjsoft.www.myencryptiondemo.aes.AesUtil
import cn.mtjsoft.www.myencryptiondemo.base64.Base64Util
import cn.mtjsoft.www.myencryptiondemo.md5.MD5Util
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
        val dataString = "我是测试明文"
        println(dataString)
        val encrypt = AesUtil.encrypt(dataString.toByteArray(), key)
        val encryptHexStr = Util.byte2HexStr(encrypt)
        println("加密: $encryptHexStr")
        val decryptHexStr = String(AesUtil.decrypt(encrypt, key))
        println("解密: $decryptHexStr")
    }

    @Test
    fun base64Test(){
        val dataString = "我是测试明文2"
        println(dataString)
        val encode = Base64Util.encode(dataString.toByteArray())
        println("base64编码: $encode")
        println("base64解码: ${String(Base64Util.decode(encode))}")
    }

    @Test
    fun md5Test(){
        val dataString = "我是测试明文3"
        println(dataString)
        println("md5: ${MD5Util.stringMD5(dataString)}")
    }
}