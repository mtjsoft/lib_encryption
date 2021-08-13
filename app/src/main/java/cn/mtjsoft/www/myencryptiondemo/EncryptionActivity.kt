package cn.mtjsoft.www.myencryptiondemo

import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import cn.mtjsoft.lib_encryption.AES.AESUtil
import cn.mtjsoft.lib_encryption.RSA.RSAUtil
import java.security.KeyPair

/**
 * type:
 * 0  AES, 1 BASE64, 2  MD5, 3 RSA, 4  SHA, 5  SM2, 6  SM3, 7  SM4
 */
class EncryptionActivity : AppCompatActivity(), View.OnClickListener {

    var type = 0

    private lateinit var enEditText: EditText
    private lateinit var deEditText: EditText

    private var key = ByteArray(0)

    private var keyPair : KeyPair ?= null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_encryption)
        enEditText = findViewById(R.id.et_top)
        deEditText = findViewById(R.id.et_bottom)
        val btn_de: Button = findViewById(R.id.btn_de)
        type = intent.getIntExtra("type", 0)
        title = intent.getStringExtra("name")
        btn_de.visibility = View.VISIBLE
        when (type) {
            0 -> {
                key = AESUtil.generateKey()
            }
            2, 4, 6 -> {
                btn_de.visibility = View.GONE
            }
            3 -> {
                keyPair = RSAUtil.generateRSAKeyPair()
            }
            5 -> {
            }
            7 -> {
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
                encrypt()
            }
            R.id.btn_de -> {
                val deString = deEditText.text.trim().toString()
                if (deString.isEmpty()) {
                    Toast.makeText(this, "请输入待解密数据", Toast.LENGTH_SHORT).show()
                    return
                }
                decrypt()
            }
        }
    }

    private fun encrypt() {
        when (type) {
            0 -> {
            }
            1 -> {
            }
            2 -> {
            }
            3 -> {
            }
            4 -> {
            }
            5 -> {
            }
            6 -> {
            }
            7 -> {
            }
        }
    }

    private fun decrypt() {
        when (type) {
            0 -> {
            }
            1 -> {
            }
            3 -> {
            }
            5 -> {
            }
            7 -> {
            }
            else -> {
                Toast.makeText(this, "无解密操作", Toast.LENGTH_SHORT).show()
            }
        }
    }
}