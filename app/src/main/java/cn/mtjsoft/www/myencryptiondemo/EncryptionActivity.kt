package cn.mtjsoft.www.myencryptiondemo

import android.content.Context
import android.os.Bundle
import android.view.View
import android.view.inputmethod.InputMethodManager
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import cn.mtjsoft.lib_encryption.AES.AESUtil
import cn.mtjsoft.lib_encryption.BASE64.Base64Util
import cn.mtjsoft.lib_encryption.MD5.MD5Util
import cn.mtjsoft.lib_encryption.RSA.RSAUtil
import cn.mtjsoft.lib_encryption.SHA.SHAUtil
import cn.mtjsoft.lib_encryption.SM2.SM2Util
import cn.mtjsoft.lib_encryption.SM3.SM3Util
import cn.mtjsoft.lib_encryption.SM4.SM4Util
import cn.mtjsoft.lib_encryption.utils.Util
import java.security.KeyPair

/**
 * type:
 * 0  AES, 1 BASE64, 2  MD5, 3 RSA, 4  SHA, 5  SM2, 6  SM3, 7  SM4
 */
class EncryptionActivity : AppCompatActivity(), View.OnClickListener {

    var type = 0

    private lateinit var enEditText: EditText
    private lateinit var deEditText: EditText

    // AES
    private var keyAES = ByteArray(0)

    // RSA
    private var keyPair: KeyPair? = null

    // SM2
    private var publicKeySM2 = ByteArray(0)
    private var privateKeySM2 = ByteArray(0)

    // SM4
    private var keySM4 = ByteArray(0)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_encryption)
        enEditText = findViewById(R.id.et_top)
        deEditText = findViewById(R.id.et_bottom)
        val btn_de: Button = findViewById(R.id.btn_de)
        type = intent.getIntExtra("type", 0)
        title = intent.getStringExtra("name")
        btn_de.visibility = View.VISIBLE
        // 根据类型，先生成密钥
        when (type) {
            0 -> {
                keyAES = AESUtil.generateKey()
            }
            2, 4, 6 -> {
                btn_de.visibility = View.GONE
            }
            3 -> {
                keyPair = RSAUtil.generateRSAKeyPair()
            }
            5 -> {
                val key = SM2Util.generateKeyPair()
                publicKeySM2 = key[0]
                privateKeySM2 = key[1]
            }
            7 -> {
                keySM4 = SM4Util.createSM4Key()
            }
        }
    }

    override fun onClick(p0: View) {
        when (p0.id) {
            R.id.btn_en -> {
                val enString = enEditText.text.trim().toString()
                if (enString.isEmpty()) {
                    Toast.makeText(this, "请输入待加密数据", Toast.LENGTH_SHORT).show()
                    return
                }
                val manager: InputMethodManager = getSystemService(Context.INPUT_METHOD_SERVICE) as InputMethodManager
                manager.hideSoftInputFromWindow(p0.windowToken, InputMethodManager.HIDE_NOT_ALWAYS)
                encrypt(enString)
            }
            R.id.btn_de -> {
                val deString = deEditText.text.trim().toString()
                if (deString.isEmpty()) {
                    Toast.makeText(this, "请输入待解密数据", Toast.LENGTH_SHORT).show()
                    return
                }
                val manager: InputMethodManager = getSystemService(Context.INPUT_METHOD_SERVICE) as InputMethodManager
                manager.hideSoftInputFromWindow(p0.windowToken, InputMethodManager.HIDE_NOT_ALWAYS)
                decrypt(deString)
            }
        }
    }

    private fun encrypt(dataString: String) {
        val enString = when (type) {
            0 -> {
                Util.byte2HexStr(AESUtil.encrypt(dataString.toByteArray(), keyAES))
            }
            1 -> {
                Base64Util.encode(dataString.toByteArray())
            }
            2 -> {
                MD5Util.stringMD5(dataString)
            }
            3 -> {
                Util.byte2HexStr(RSAUtil.encryptByPublicKey(dataString.toByteArray(), keyPair?.public))
            }
            4 -> {
                SHAUtil.stringSHA(dataString, SHAUtil.SHA1)
            }
            5 -> {
                Util.byte2HexStr(SM2Util.encrypt(publicKeySM2, dataString.toByteArray()))
            }
            6 -> {
                SM3Util.encryptInner(dataString)
            }
            7 -> {
                Util.byte2HexStr(SM4Util.encrypt(dataString.toByteArray(), keySM4, SM4Util.SM4_CBC_PKCS5, ByteArray(16)))
            }
            else -> ""
        }
        deEditText.setText(enString)
        enEditText.setText("")
        Toast.makeText(this, "加密完成", Toast.LENGTH_SHORT).show()
    }

    private fun decrypt(dataString: String) {
        val deString = when (type) {
            0 -> {
                String(AESUtil.decrypt(Util.hexStr2Bytes(dataString), keyAES))
            }
            1 -> {
                String(Base64Util.decode(dataString))
            }
            3 -> {
                String(RSAUtil.decryptByPrivateKey(Util.hexStr2Bytes(dataString), keyPair?.private))
            }
            5 -> {
                String(SM2Util.decrypt(privateKeySM2, Util.hexStr2Bytes(dataString)))
            }
            7 -> {
                String(SM4Util.decrypt(Util.hexStr2Bytes(dataString), keySM4, SM4Util.SM4_CBC_PKCS5, ByteArray(16)))
            }
            else -> ""
        }
        enEditText.setText(deString)
        deEditText.setText("")
        Toast.makeText(this, "解密完成", Toast.LENGTH_SHORT).show()
    }
}