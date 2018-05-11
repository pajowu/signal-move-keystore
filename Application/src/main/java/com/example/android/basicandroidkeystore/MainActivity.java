/*
* Copyright 2013 The Android Open Source Project
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/


package com.example.android.basicandroidkeystore;

import android.graphics.Color;
import android.os.Bundle;
import android.support.v4.app.FragmentTransaction;
import android.text.Html;
import android.widget.TextView;
import android.view.Menu;

import com.example.android.common.activities.SampleActivityBase;
import com.example.android.common.logger.Log;
import com.example.android.common.logger.LogFragment;
import com.example.android.common.logger.LogWrapper;
import com.example.android.common.logger.MessageOnlyLogFilter;
import com.example.android.common.logger.Log;

import android.content.Context;
import android.os.Build;
import android.os.Bundle;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.v4.app.Fragment;
import android.util.Base64;
import android.view.MenuItem;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Calendar;
import java.util.GregorianCalendar;


import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import javax.security.auth.x500.X500Principal;
/**
 * A simple launcher activity containing a summary sample description
 * and a few action bar buttons.
 */
public class MainActivity extends SampleActivityBase {

    public static final String TAG = "MainActivity";
    private String mAlias = "SignalSecret";
    public static final String FRAGTAG = "BasicAndroidKeyStoreFragment";
    private String YOUR_DATA = "*************** EDIT HERE ***********************";
    private String YOUR_IV = "***************** EDIT HERE **********************";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.main, menu);
        return true;
    }

    /** Create a chain of targets that will receive log data */
    @Override
    public void initializeLogging() {
        // Wraps Android's native log framework.
        LogWrapper logWrapper = new LogWrapper();
        // Using Log, front-end to the logging chain, emulates android.util.log method signatures.
        Log.setLogNode(logWrapper);

        // Filter strips out everything except the message text.
        MessageOnlyLogFilter msgFilter = new MessageOnlyLogFilter();
        logWrapper.setNext(msgFilter);

        // On screen logging via a fragment with a TextView.
        LogFragment logFragment = (LogFragment) getSupportFragmentManager()
        .findFragmentById(R.id.log_fragment);

        Log.i(TAG, "Ready");
        KeyStore.Entry entry = null;
        try{

        // BEGIN_INCLUDE(sign_load_keystore)
            KeyStore ks = KeyStore.getInstance(SecurityConstants.KEYSTORE_PROVIDER_ANDROID_KEYSTORE);

        // Weird artifact of Java API.  If you don't have an InputStream to load, you still need
        // to call "load", or it'll crash.
            ks.load(null);

        // Load the key pair from the Android Key Store
            entry = ks.getEntry(mAlias, null);
        } catch (Exception e) {}
        /* If the entry is null, keys were never stored under this alias.
         * Debug steps in this situation would be:
         * -Check the list of aliases by iterating over Keystore.aliases(), be sure the alias
         *   exists.
         * -If that's empty, verify they were both stored and pulled from the same keystore
         *   "AndroidKeyStore"
         */
        if (entry == null) {
            Log.w(TAG, "No key found under alias: " + mAlias);
            Log.w(TAG, "Exiting signData()...");
            return;
        }

        /* If entry is not a KeyStore.PrivateKeyEntry, it might have gotten stored in a previous
         * iteration of your application that was using some other mechanism, or been overwritten
         * by something else using the same keystore with the same alias.
         * You can determine the type using entry.getClass() and debug from there.
         */
        if (!(entry instanceof KeyStore.SecretKeyEntry)) {
            Log.w(TAG, "Not an instance of a SecretKeyEntry");
            Log.w(TAG, "Exiting signData()...");
            return;
        }

        Log.w(TAG, ((KeyStore.SecretKeyEntry) entry).getSecretKey().getFormat());
        SecretKey secretKey = null;
        try {
            secretKey = ((KeyStore.SecretKeyEntry) entry).getSecretKey();
        }catch (Exception e) {
            Log.d(TAG, "sk", e);
        }
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("AES/GCM/NoPadding");
        }catch (Exception e) {
            Log.d(TAG, "ci", e);
        }
        try {
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, Base64.decode(YOUR_IV, Base64.NO_WRAP | Base64.NO_PADDING)));
        } catch (Exception e) {
            Log.d(TAG, "cihper init", e);
        }
        byte[] descrypted_secret = null;
        try {
            descrypted_secret = cipher.doFinal(Base64.decode(YOUR_DATA, Base64.NO_WRAP | Base64.NO_PADDING));
        } catch (Exception e) {
            Log.d(TAG, "secret", e);
        }
        String result = null;
        try {
            result = Base64.encodeToString(descrypted_secret, Base64.DEFAULT);
        }  catch (Exception e) {
            Log.d(TAG, "result", e);
        }
            // END_INCLUDE(sign_data)
        Log.d(TAG, "****************************************");

        Log.d(TAG, result);
        Log.d(TAG, "****************************************");

    }
}
