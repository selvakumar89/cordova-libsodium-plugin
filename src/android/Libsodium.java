package com.rdd.plugin;

import android.util.Base64;


import org.abstractj.kalium.SodiumConstants;
import org.apache.cordova.*;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.Arrays;

import static org.abstractj.kalium.NaCl.sodium;
import static org.abstractj.kalium.SodiumConstants.ZERO_BYTES;
import static org.abstractj.kalium.crypto.Util.prependZeros;
import static org.abstractj.kalium.crypto.Util.removeZeros;

public class Libsodium extends CordovaPlugin {
    
    @Override
    public boolean execute(String action, JSONArray data, CallbackContext callbackContext) throws JSONException {
        
        if (action.equals("initKey")) {
            byte[] PublicKey = new byte[SodiumConstants.PUBLICKEY_BYTES];
            byte[] SecretKey = new byte[SodiumConstants.SECRETKEY_BYTES];
            sodium().crypto_box_curve25519xsalsa20poly1305_keypair(PublicKey, SecretKey);
            byte[] Nonce = new byte[SodiumConstants.XSALSA20_POLY1305_SECRETBOX_NONCEBYTES];
            sodium().randombytes(Nonce, Nonce.length);
            
            JSONObject json = new JSONObject();
            json.put("pk", Base64.encodeToString(PublicKey, Base64.DEFAULT));
            json.put("sk", Base64.encodeToString(SecretKey, Base64.DEFAULT));
            callbackContext.success(json);
            return true;
            
        }else if (action.equals("cryptobox_open")) {
            
            byte[] serverCipher = Base64.decode(data.getString(0), Base64.DEFAULT);
            byte[] serverPk = Base64.decode(data.getString(1), Base64.DEFAULT);
            byte[] serverNonce = Base64.decode(data.getString(2), Base64.DEFAULT);
            byte[] mySk = Base64.decode(data.getString(3), Base64.DEFAULT);
            
            /* initilize unsigned message */
            byte[] unsigned_message = new byte[serverCipher.length];  // plain text
            int ret =sodium().crypto_box_curve25519xsalsa20poly1305_open(unsigned_message,serverCipher,unsigned_message.length,serverNonce,serverPk,mySk);
            if(ret == 0) {
                unsigned_message = removeZeros(ZERO_BYTES, unsigned_message);
                System.out.println("message :" + unsigned_message + " message length :"+unsigned_message.length);
                String plainText = new String(unsigned_message);
                JSONObject json = new JSONObject();
                json.put("plainText", plainText);
                callbackContext.success(json);
            }
            else {
                callbackContext.error("failed");
            }
            return true;
        }else if (action.equals("cryptobox_create")) {
            
            byte[] message = data.getString(0).getBytes(); // convert message string to byte array
            message = prependZeros(ZERO_BYTES, message); // mandatory
            int messageLen = message.length;
            byte[] ServerPublicKey = Base64.decode(data.getString(1), Base64.DEFAULT);
            byte[] SecretKey = Base64.decode(data.getString(2), Base64.DEFAULT);
            byte[] Nonce = new byte[SodiumConstants.XSALSA20_POLY1305_SECRETBOX_NONCEBYTES];
            sodium().randombytes(Nonce, Nonce.length);
            
            // ** ciphertext initilaize
            byte[] ClientCt = new byte[message.length];
            int CtLen = ClientCt.length;
            if(sodium().crypto_box_curve25519xsalsa20poly1305(ClientCt,message,messageLen,Nonce,ServerPublicKey,SecretKey) != 0){
                callbackContext.error("Failed");
            }else {
                byte[] removedZerosClientCt = Arrays.copyOfRange(ClientCt, 16, ClientCt.length);
                JSONObject json = new JSONObject();
                json.put("ct", Base64.encodeToString(removedZerosClientCt, Base64.DEFAULT));
                json.put("nonce", Base64.encodeToString(Nonce, Base64.DEFAULT));
                callbackContext.success(json);
            }
            return true;
        }else {
            return false;
        }
    }
}
