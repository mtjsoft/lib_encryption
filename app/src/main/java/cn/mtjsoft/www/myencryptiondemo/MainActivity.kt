package cn.mtjsoft.www.myencryptiondemo

import android.content.Intent
import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity(), View.OnClickListener {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
    }

    override fun onClick(p0: View) {
        val intent = Intent(this, EncryptionActivity::class.java)
        var type = EncryptionType.AES
        when (p0.id) {
            R.id.btn_aes -> {
                type = EncryptionType.AES
            }
            R.id.btn_base64 -> {
                type = EncryptionType.BASE64
            }
            R.id.btn_md5 -> {
                type = EncryptionType.MD5
            }
            R.id.btn_rsa -> {
                type = EncryptionType.RSA
            }
            R.id.btn_sha -> {
                type = EncryptionType.SHA
            }
            R.id.btn_sm2 -> {
                type = EncryptionType.SM2
            }
            R.id.btn_sm3 -> {
                type = EncryptionType.SM3
            }
            R.id.btn_sm4 -> {
                type = EncryptionType.SM4
            }
        }
        intent.putExtra("type", type)
        startActivity(intent)
    }
}