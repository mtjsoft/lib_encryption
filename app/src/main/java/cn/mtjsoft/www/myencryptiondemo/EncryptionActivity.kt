package cn.mtjsoft.www.myencryptiondemo

import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AppCompatActivity

class EncryptionActivity : AppCompatActivity(), View.OnClickListener {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_encryption)

        val type = intent.getSerializableExtra("type")
    }

    override fun onClick(p0: View) {
    }
}