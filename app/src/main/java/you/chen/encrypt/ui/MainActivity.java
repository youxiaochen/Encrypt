package you.chen.encrypt.ui;

import android.os.Bundle;
import android.view.View;

import androidx.appcompat.app.AppCompatActivity;

import you.chen.encrypt.R;
import you.chen.encrypt.Test;

public class MainActivity extends AppCompatActivity implements View.OnClickListener {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        findViewById(R.id.bt0).setOnClickListener(this);
        findViewById(R.id.bt1).setOnClickListener(this);
        findViewById(R.id.bt2).setOnClickListener(this);
        findViewById(R.id.bt3).setOnClickListener(this);
        findViewById(R.id.bt4).setOnClickListener(this);
        findViewById(R.id.bt5).setOnClickListener(this);
    }

    @Override
    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.bt0:
                Test.testBase64();
                break;
            case R.id.bt1:
                Test.testMD5();
                break;
            case R.id.bt2:
                Test.testEcbAES();
                break;
            case R.id.bt3:
                Test.testCbcAES();
                break;
            case R.id.bt4:
                Test.testRsa();
                break;
            case R.id.bt5:
                Test.createRsaKey();
                break;
        }
    }

}
