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
        var type = 0
        var name = "AES"
        when (p0.id) {
            R.id.btn_aes -> {
                type = 0
                name = "AES"
            }
            R.id.btn_base64 -> {
                type = 1
                name = "BASE64"
            }
            R.id.btn_md5 -> {
                type = 2
                name = "MD5"
            }
            R.id.btn_rsa -> {
                type = 3
                name = "RSA"
            }
            R.id.btn_sha -> {
                type = 4
                name = "SHA"
            }
            R.id.btn_sm2 -> {
                type = 5
                name = "SM2"
            }
            R.id.btn_sm3 -> {
                type = 6
                name = "SM3"
            }
            R.id.btn_sm4 -> {
                type = 7
                name = "SM4"
            }
        }
        intent.putExtra("type", type)
        intent.putExtra("name", name)
        startActivity(intent)
    }
}