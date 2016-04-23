/*
  Copyright (c) 2016, Princeton University.
  All rights reserved.
  
  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are 
  met:
  * Redistributions of source code must retain the above copyright 
  notice, this list of conditions and the following disclaimer.
  * Redistributions in binary form must reproduce the above 
  copyright notice, this list of conditions and the following disclaimer 
  in the documentation and/or other materials provided with the 
  distribution.
  * Neither the name of Princeton University nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.
  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND 
  CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR 
  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF 
  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
  POSSIBILITY OF SUCH DAMAGE.
 */

package org.coniks.coniks_test_client;

import java.security.*;
import java.security.KeyPair;
import java.security.spec.*;
import java.security.interfaces.*;
import javax.crypto.*;
import java.math.BigInteger;

// TODO(mrochlin)
// Should use protected keystore instead of just file streams
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

/** Implements all operations involving digital signatures
 * that a CONIKS client must perform.
 *
 *@author Michael Rochlin
 */
public class SignatureOps{

    /*********************************************************************
     * The following code is used in the reference client, but does not 
     * use a keystore. Instead these functions simply use regular, unprotected
     * files. Future implmentations should use protected keystores 
     *********************************************************************/


    // TODO(mrochlin)
    // Should use protected keystore instead of just file streams
    public static boolean unsafeSaveDSAKeyPair(KeyPair kp) {
        return unsafeSaveDSAKeyPairToFile(kp, ClientConfig.KEYSTORE_PATH);
    }

    // TODO(mrochlin)
    // Should use protected keystore instead of just file streams
    public static boolean unsafeSavePublicKey(DSAPublicKey pubKey) {
        return unsafeSavePublicKeyToFile(pubKey, ClientConfig.KEYSTORE_PATH + "_pub");
    }

    // TODO(mrochlin)
    // Should use protected keystore instead of just file streams
    public static boolean unsafeSavePrivateKey(DSAPrivateKey prKey) {
        return unsafeSavePrivateKeyToFile(prKey, ClientConfig.KEYSTORE_PATH + "_pr");
    }

    // TODO(mrochlin)
    // Should use protected keystore instead of just file streams
    public static boolean unsafeSaveDSAKeyPair(KeyPair kp, String username) {
        String pubPath = ClientConfig.KEYSTORE_PATH + "_" + username + "_pub";
        String prPath = ClientConfig.KEYSTORE_PATH + "_" + username + "_pr";
        ClientLogger.log("Saving to: " + pubPath + " " + prPath);
        return unsafeSavePublicKeyToFile((DSAPublicKey) kp.getPublic(), pubPath) 
                && unsafeSavePrivateKeyToFile((DSAPrivateKey) kp.getPrivate(), prPath);
    }

    // TODO(mrochlin)
    // Should use protected keystore instead of just file streams
    public static boolean unsafeSavePublicKey(DSAPublicKey pubKey, String username) {
        return unsafeSavePublicKeyToFile(pubKey, ClientConfig.KEYSTORE_PATH + "_" + username + "_pub");
    }

    // TODO(mrochlin)
    // Should use protected keystore instead of just file streams
    public static boolean unsafeSavePrivateKey(DSAPrivateKey prKey, String username) {
        return unsafeSavePrivateKeyToFile(prKey, ClientConfig.KEYSTORE_PATH + "_" + username + "_pr");
    }



    // TODO(mrochlin)
    // Should use protected keystore instead of just file streams
    public static boolean unsafeSaveDSAKeyPairToFile(KeyPair kp, String filePath) {
        String pubPath = filePath + "_pub";
        String prPath = filePath + "_pr";
        return unsafeSavePublicKeyToFile((DSAPublicKey) kp.getPublic(), pubPath) 
                && unsafeSavePrivateKeyToFile((DSAPrivateKey) kp.getPrivate(), prPath);
    }

    // TODO(mrochlin)
    // Should use protected keystore instead of just file streams
    public static boolean unsafeSavePublicKeyToFile(DSAPublicKey pubKey, String fileName) {
        try {
            ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(fileName));
            out.writeObject(pubKey);
            out.close();
        }
        catch (Exception e) {
            return false;
        }
        return true;
    }

    // TODO(mrochlin)
    // Should use protected keystore instead of just file streams
    public static boolean unsafeSavePrivateKeyToFile(DSAPrivateKey prKey, String fileName) {
        try {
            ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(fileName));
            out.writeObject(prKey);
            out.close();
        }
        catch (Exception e) {
            return false;
        }
        return true;
    }

    // TODO(mrochlin)
    // Should use protected keystore instead of just file streams
    public static KeyPair unsafeLoadDSAKeyPair() {
        return unsafeLoadDSAKeyPairFromFile(ClientConfig.KEYSTORE_PATH + "_pub", 
                                            ClientConfig.KEYSTORE_PATH + "_pr");
    }

    // TODO(mrochlin)
    // Should use protected keystore instead of just file streams
    public static DSAPublicKey unsafeLoadDSAPublicKey() {
        return unsafeLoadDSAPublicKeyFromFile(ClientConfig.KEYSTORE_PATH + "_pub");
    }

    // TODO(mrochlin)
    // Should use protected keystore instead of just file streams
    public static DSAPrivateKey unsafeLoadDSAPrivateKey() {
        return unsafeLoadDSAPrivateKeyFromFile(ClientConfig.KEYSTORE_PATH + "_pr");
    }

    // TODO(mrochlin)
    // Should use protected keystore instead of just file streams
    public static KeyPair unsafeLoadDSAKeyPair(String username) {
        return unsafeLoadDSAKeyPairFromFile(ClientConfig.KEYSTORE_PATH + "_" + username + "_pub", 
                                    ClientConfig.KEYSTORE_PATH + "_" + username + "_pr");
    }

    // TODO(mrochlin)
    // Should use protected keystore instead of just file streams
    public static DSAPublicKey unsafeLoadDSAPublicKey(String username) {
        return unsafeLoadDSAPublicKeyFromFile(ClientConfig.KEYSTORE_PATH + "_" + username + "_pub");
    }

    // TODO(mrochlin)
    // Should use protected keystore instead of just file streams
    public static DSAPrivateKey unsafeLoadDSAPrivateKey(String username) {
        return unsafeLoadDSAPrivateKeyFromFile(ClientConfig.KEYSTORE_PATH + "_" + username + "_pr");
    }


    // TODO(mrochlin)
    // Should use protected keystore instead of just file streams
    public static KeyPair unsafeLoadDSAKeyPairFromFile(String pubKeyFile, String prKeyFile) {
        DSAPublicKey pubKey = unsafeLoadDSAPublicKeyFromFile(pubKeyFile);
        DSAPrivateKey prKey = unsafeLoadDSAPrivateKeyFromFile(prKeyFile);
        if (pubKey == null || prKey == null) {
            return null;
        }
        return new KeyPair((PublicKey) pubKey, (PrivateKey) prKey);
    }

    // TODO(mrochlin)
    // Should use protected keystore instead of just file streams
    public static DSAPublicKey unsafeLoadDSAPublicKeyFromFile(String pubKeyFile) {
        try {
            ObjectInputStream keyIn = new ObjectInputStream(new FileInputStream(pubKeyFile));
            DSAPublicKey pubKey = (DSAPublicKey) keyIn.readObject();
            keyIn.close();
            return pubKey;
        }
        catch (Exception e) {
            return null;
        }
    }

    // TODO(mrochlin)
    // Should use protected keystore instead of just file streams
    public static DSAPrivateKey unsafeLoadDSAPrivateKeyFromFile(String prKeyFile) {
        try {
            ObjectInputStream keyIn = new ObjectInputStream(new FileInputStream(prKeyFile));
            DSAPrivateKey prKey = (DSAPrivateKey) keyIn.readObject();
            keyIn.close();
            return prKey;
        }
        catch (Exception e) {
            return null;
        }
    }

    /** Makes a DSA PublicKey from the given parameters */
    public static PublicKey makeDSAPublicKeyFromParams(BigInteger p, BigInteger q, BigInteger g, BigInteger y) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("DSA");
            KeySpec publicKeySpec = new DSAPublicKeySpec(y, p, q, g);
            return keyFactory.generatePublic(publicKeySpec);
        }
        catch(InvalidParameterException e) {
            ClientLogger.error("The given key is invalid.");
        }
        catch (InvalidKeySpecException e) {
            ClientLogger.error("The given key params are invalid.");
        }
        catch(NoSuchAlgorithmException e){
            ClientLogger.error("DSA is invalid for some reason.");
        }
        return null;
    }

    /** Verifies @code{msg} and the @code{sig} using the DSA PublicKey @code{pk} */
    public static boolean verifySigFromDSA(byte[] msg, byte[] sig, PublicKey pk) {
        try {
            Signature verifyalg = Signature.getInstance("DSA");
            verifyalg.initVerify(pk);
            verifyalg.update(msg);
            if (!verifyalg.verify(sig)) {
                ClientLogger.error("Failed to validate signature");
                return false;
            }
            return true;
        }
        catch(NoSuchAlgorithmException e){
            ClientLogger.error("DSA is invalid for some reason.");
        }
        catch(InvalidKeyException e){
            ClientLogger.error("The given key is invalid.");
        }
        catch(SignatureException e){
            ClientLogger.error("The format of the input is invalid: "+e.getMessage());
        }
        return false;
    }

    /** Signs @code{msg} using DSAPrivateKey @code{prk} 
        Returns null on an error 
        Throws @code{InvalidKeyException} if @code{prk} is null */
    public static byte[] sign(byte[] msg, DSAPrivateKey prk) throws InvalidKeyException {
        if (prk == null) {
            ClientLogger.error("The given key is invalid.");
            throw new InvalidKeyException();
        }
        try {
            Signature sigProcess = Signature.getInstance("DSA");
            sigProcess.initSign(prk);
            sigProcess.update(msg);
            return sigProcess.sign();
        }
        catch(NoSuchAlgorithmException e){
            ClientLogger.error("DSA is invalid for some reason.");
        }
        catch(InvalidKeyException e){
            ClientLogger.error("The given key is invalid.");
        }
        catch(SignatureException e){
            ClientLogger.error("The format of the input is invalid: "+e.getMessage());
        }
        return null;
    }


} //ends SignatureOps class
