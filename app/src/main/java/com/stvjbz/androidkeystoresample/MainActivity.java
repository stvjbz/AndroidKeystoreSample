package com.stvjbz.androidkeystoresample;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import org.w3c.dom.Text;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "KeyStoreProviderSample";

    private static final String KEY_PROVIDER = "AndroidKeyStore";
    private static final String KEY_ALIAS = "sample key";
    //TODO:API幾つ対応か確認 API19以上だと良い(v4.4 KitKat~)
    //private static final String ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"; // API23~
    private static final String ALGORITHM = "RSA/ECB/PKCS1Padding"; //API 18+

    private KeyStore mKeyStore = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        prepareKeyStore();

        Button buttton = (Button)findViewById(R.id.button);
        buttton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                //元のテキスト
                TextView view;
                EditText edit_text;
                edit_text = (EditText)findViewById(R.id.editText);
                String plainText = edit_text.getText().toString();

                // encrypt 暗号化テキスト表示
                String encryptedText = encryptString(mKeyStore, KEY_ALIAS, plainText);
                view = (TextView)findViewById(R.id.textView2);
                view.setText(encryptedText);

                // decypt 復号済みテキスト表示
                String decryptedText = decryptString(mKeyStore, KEY_ALIAS, encryptedText);
                view = (TextView)findViewById(R.id.textView3);
                view.setText(decryptedText);
            }
        });

        mKeyStoreManager = AndroidKeyStoreManager.getInstance(this);
        test();
    }

    private AndroidKeyStoreManager mKeyStoreManager;
    private void test() {
        String plainText = "あいうえお";
        byte[] encryptedBytes = mKeyStoreManager.encrypt(plainText.getBytes());
        byte[] decryptedBytes = mKeyStoreManager.decrypt(encryptedBytes);
        String encryptedText = new String(encryptedBytes);
        String decryptedText = new String(decryptedBytes);
        Log.d("KeyStoreTest", encryptedText); // -> hogehoge
        Log.d("KeyStoreTest", decryptedText); // -> hogehoge
    }

    private void prepareKeyStore() {
        try {
            // Android Keystoreのロード
            mKeyStore = KeyStore.getInstance("AndroidKeyStore");//TODO:ここに入れているものの役割は何？
            mKeyStore.load(null);
            createNewKey(mKeyStore, KEY_ALIAS);
        } catch (Exception e) {
            Log.e(TAG,e.toString());
        }

    }
    /**
     * Create new key pair if needed.
     *
     * Create RSA key pair for encryption/decryption using RSA OAEP.
     * See KeyGenParameterSpec document.
     *
     * @param keyStore key store
     * @param alias key alias
     */
    private void createNewKey(KeyStore keyStore, String alias) {
        try {
            // 鍵ペアがなければKeyPairGeneratorを使って新しくpublic/private keyを生成する。
            // Create new key pair if needed.
            if (!keyStore.containsAlias(alias)) {

                // Call API require level 23
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                        KeyProperties.KEY_ALGORITHM_RSA, KEY_PROVIDER);
                keyPairGenerator.initialize(
                    new KeyGenParameterSpec.Builder(
                            alias,
                            KeyProperties.PURPOSE_DECRYPT)
                            //test.setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                            //.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                            .build());
                    keyPairGenerator.generateKeyPair();
            }
        } catch (Exception e) {
            Log.e(TAG, e.toString());
        }
    }
    /**
     * Encrypt string text 暗号化
     *
     * @param keyStore key store used
     * @param alias key alias
     * @param plainText string to be encrypted
     *
     * @return base64 encoded cipher text
     */
    private String encryptString(KeyStore keyStore, String alias, String plainText) {
        String encryptedText = null;
        try {
            // 公開鍵 KeyStore証明証から取得
            PublicKey publicKey = keyStore.getCertificate(alias).getPublicKey();

            // TODO: これの役割
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            // public keyで暗号化したデータを保持する
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            // CipherOutputStreamに暗号データが出力される
            CipherOutputStream cipherOutputStream = new CipherOutputStream(
                    outputStream, cipher);
            cipherOutputStream.write(plainText.getBytes("UTF-8"));
            cipherOutputStream.close();

            byte[] bytes = outputStream.toByteArray();
            // Base64 encodeしている
            encryptedText = Base64.encodeToString(bytes, Base64.DEFAULT);

        } catch (Exception e) {
            Log.e(TAG, e.toString());
        }
        return encryptedText;

    }

    /**
     * Decrypt base64 encoded cipher text 復号化
     *
     * @param keyStore key store used
     * @param alias key alias
     * @param encryptedText base64 encoded cipher text
     *
     * @return plain text string
     */
    private String decryptString(KeyStore keyStore, String alias, String encryptedText) {
        String plainText = null;
        try {
            // 秘密鍵 keyStoreから取得
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            System.out.println("DDDDDDDDDDDDDDDDDD");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            System.out.println("CCCCCCCCCCCCCCCCCC");

            // CipherInputStreamから復号データを読み出すことができる。
            CipherInputStream cipherInputStream = new CipherInputStream(
                    new ByteArrayInputStream(Base64.decode(encryptedText, Base64.DEFAULT)), cipher);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            int b;
            while ((b = cipherInputStream.read()) != -1) {
                outputStream.write(b);
            }
            outputStream.close();
            plainText = outputStream.toString("UTF-8");
            System.out.println("CCCCCCCCCCCCCCCCCC");

        } catch (Exception e) {
            Log.e(TAG, e.toString());
        }
        return plainText;
    }

}
