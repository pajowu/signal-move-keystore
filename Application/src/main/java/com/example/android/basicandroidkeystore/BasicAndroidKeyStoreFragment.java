/*
* Copyright (C) 2013 The Android Open Source Project
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

package com.example.android.basicandroidkeystore;

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

public class BasicAndroidKeyStoreFragment extends Fragment {

    public static final String TAG = "KeyStoreFragment";

    // BEGIN_INCLUDE(values)

    public static final String SAMPLE_ALIAS = "SignalSecret";

    // Some sample data to sign, and later verify using the generated signature.
    public static final String SAMPLE_INPUT="Hello, Android!";

    // Just a handy place to store the signature in between signing and verifying.
    public String mSignatureStr = null;

    // You can store multiple key pairs in the Key Store.  The string used to refer to the Key you
    // want to store, or later pull, is referred to as an "alias" in this case, because calling it
    // a key, when you use it to retrieve a key, would just be irritating.
    private String mAlias = null;

    // END_INCLUDE(values)

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setHasOptionsMenu(true);
        setAlias(SAMPLE_ALIAS);
        try {signData();} catch (Exception e) {}

    }

    @Override
    public void onActivityCreated(Bundle savedInstanceState) {
        super.onActivityCreated(savedInstanceState);
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            case R.id.btn_create_keys:
                try {
                    createKeys(getActivity());
                    Log.d(TAG, "Keys created");
                    return true;
                } catch (NoSuchAlgorithmException e) {
                    Log.w(TAG, "RSA not supported", e);
                } catch (InvalidAlgorithmParameterException e) {
                    Log.w(TAG, "No such provider: AndroidKeyStore");
                } catch (NoSuchProviderException e) {
                    Log.w(TAG, "Invalid Algorithm Parameter Exception", e);
                } catch (NoSuchPaddingException e) {
                    Log.w(TAG, "NoSuchPaddingException", e);
                } catch (BadPaddingException e) {
                    Log.w(TAG, "BadPaddingException", e);
                } catch (InvalidKeyException e) {
                    Log.w(TAG, "InvalidKeyException", e);
                } catch (IllegalBlockSizeException e) {
                    Log.w(TAG, "IllegalBlockSizeException", e);
                } catch (Exception e) {
                    Log.w(TAG, "errir", e);
                }
                return true;
            case R.id.btn_sign_data:
                try {
                    mSignatureStr = signData();
                } catch (KeyStoreException e) {
                    Log.w(TAG, "KeyStore not Initialized", e);
                } catch (UnrecoverableEntryException e) {
                    Log.w(TAG, "KeyPair not recovered", e);
                } catch (NoSuchAlgorithmException e) {
                    Log.w(TAG, "RSA not supported", e);
                } catch (InvalidKeyException e) {
                    Log.w(TAG, "Invalid Key", e);
                } catch (SignatureException e) {
                    Log.w(TAG, "Invalid Signature", e);
                } catch (IOException e) {
                    Log.w(TAG, "IO Exception", e);
                } catch (CertificateException e) {
                    Log.w(TAG, "Error occurred while loading certificates", e);
                }
                Log.d(TAG, "Signature: " + mSignatureStr);
                return true;

            case R.id.btn_verify_data:
                boolean verified = false;
                try {
                    if (mSignatureStr != null) {
                        verified = verifyData(SAMPLE_INPUT, mSignatureStr);
                    }
                } catch (KeyStoreException e) {
                    Log.w(TAG, "KeyStore not Initialized", e);
                } catch (CertificateException e) {
                    Log.w(TAG, "Error occurred while loading certificates", e);
                } catch (NoSuchAlgorithmException e) {
                    Log.w(TAG, "RSA not supported", e);
                } catch (IOException e) {
                    Log.w(TAG, "IO Exception", e);
                } catch (UnrecoverableEntryException e) {
                    Log.w(TAG, "KeyPair not recovered", e);
                } catch (InvalidKeyException e) {
                    Log.w(TAG, "Invalid Key", e);
                } catch (SignatureException e) {
                    Log.w(TAG, "Invalid Signature", e);
                }
                if (verified) {
                    Log.d(TAG, "Data Signature Verified");
                } else {
                    Log.d(TAG, "Data not verified.");
                }
                return true;
        }
        return false;
    }

    /**
     * Creates a public and private key and stores it using the Android Key Store, so that only
     * this application will be able to access the keys.
     */
    public void createKeys(Context context) throws NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, BadPaddingException, KeyStoreException, IOException, UnrecoverableEntryException, Exception {


    }

    /**
     * Signs the data using the key pair stored in the Android Key Store.  This signature can be
     * used with the data later to verify it was signed by this application.
     * @return A string encoding of the data signature generated
     */
    public String signData() throws KeyStoreException,
            UnrecoverableEntryException, NoSuchAlgorithmException, InvalidKeyException,
            SignatureException, IOException, CertificateException {

        // BEGIN_INCLUDE(sign_load_keystore)
        KeyStore ks = KeyStore.getInstance(SecurityConstants.KEYSTORE_PROVIDER_ANDROID_KEYSTORE);

        // Weird artifact of Java API.  If you don't have an InputStream to load, you still need
        // to call "load", or it'll crash.
        ks.load(null);

        // Load the key pair from the Android Key Store
        KeyStore.Entry entry = ks.getEntry(mAlias, null);

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
            return null;
        }

        /* If entry is not a KeyStore.PrivateKeyEntry, it might have gotten stored in a previous
         * iteration of your application that was using some other mechanism, or been overwritten
         * by something else using the same keystore with the same alias.
         * You can determine the type using entry.getClass() and debug from there.
         */
        if (!(entry instanceof KeyStore.SecretKeyEntry)) {
            Log.w(TAG, "Not an instance of a SecretKeyEntry");
            Log.w(TAG, "Exiting signData()...");
            return null;
        }
        return null;


    }

    /**
     * Given some data and a signature, uses the key pair stored in the Android Key Store to verify
     * that the data was signed by this application, using that key pair.
     * @param input The data to be verified.
     * @param signatureStr The signature provided for the data.
     * @return A boolean value telling you whether the signature is valid or not.
     */
    public boolean verifyData(String input, String signatureStr) throws KeyStoreException,
            CertificateException, NoSuchAlgorithmException, IOException,
            UnrecoverableEntryException, InvalidKeyException, SignatureException {
        byte[] data = input.getBytes();
        byte[] signature;
        // BEGIN_INCLUDE(decode_signature)

        // Make sure the signature string exists.  If not, bail out, nothing to do.

        if (signatureStr == null) {
            Log.w(TAG, "Invalid signature.");
            Log.w(TAG, "Exiting verifyData()...");
            return false;
        }

        try {
            // The signature is going to be examined as a byte array,
            // not as a base64 encoded string.
            signature = Base64.decode(signatureStr, Base64.DEFAULT);
        } catch (IllegalArgumentException e) {
            // signatureStr wasn't null, but might not have been encoded properly.
            // It's not a valid Base64 string.
            return false;
        }
        // END_INCLUDE(decode_signature)

        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");

        // Weird artifact of Java API.  If you don't have an InputStream to load, you still need
        // to call "load", or it'll crash.
        ks.load(null);

        // Load the key pair from the Android Key Store
        KeyStore.Entry entry = ks.getEntry(mAlias, null);

        if (entry == null) {
            Log.w(TAG, "No key found under alias: " + mAlias);
            Log.w(TAG, "Exiting verifyData()...");
            return false;
        }

        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            Log.w(TAG, "Not an instance of a PrivateKeyEntry");
            return false;
        }

        // This class doesn't actually represent the signature,
        // just the engine for creating/verifying signatures, using
        // the specified algorithm.
        Signature s = Signature.getInstance(SecurityConstants.SIGNATURE_SHA256withRSA);

        // BEGIN_INCLUDE(verify_data)
        // Verify the data.
        s.initVerify(((KeyStore.PrivateKeyEntry) entry).getCertificate());
        s.update(data);
        return s.verify(signature);
        // END_INCLUDE(verify_data)
    }

    public void setAlias(String alias) {
        mAlias = alias;
    }
}
