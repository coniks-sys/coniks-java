/*
  Copyright (c) 2015-16, Princeton University.
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
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import javax.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Scanner;
import java.io.PrintWriter;
import java.io.*;

// coniks-java imports
import org.coniks.util.Logging;
import org.coniks.coniks_common.CommonMessaging;

/** Implements all operations involving encryption keys
 * that a CONIKS client must perform.
 *
 *@author Marcela S. Melara (melara@cs.princeton.edu)
 *@author Michael Rochlin
 */
public class KeyOps{

    /** Loads a public key from a stored file.
     *
     *@param uname the username for which to load the public key
     *@return the public key or null upon an error.
     */
    public static DSAPublicKey loadDSAPublicKeyFile (String uname) {
        String filename = ClientConfig.getUserKeysPath()+"/"+uname+".pub";
        DSAPublicKey pubKey = null;

        FileInputStream fis = null;

        try {
            fis = new FileInputStream(filename);
            byte[] keyBytes = new byte[fis.available()];
            fis.read(keyBytes);

            KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");

            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(keyBytes);

            pubKey = (DSAPublicKey) keyFactory.generatePublic(pubKeySpec);
        }
        catch (IOException e) {
            Logging.error(e.getMessage());
        }
        catch (NoSuchAlgorithmException e){
            Logging.error(e.getMessage());
        }
        catch (NoSuchProviderException e){
            Logging.error(e.getMessage());
        }
         catch(InvalidKeySpecException e){
            Logging.error(e.getMessage());
        }
        finally {
            CommonMessaging.close(fis);
        }

        return pubKey;

    }

    /** Load the CONIKS client's private key from the file.
     *
     *@param uname the username associated with the key to load
     *@return The client's private key, or {@code null}
     * in the case of an Exception.
     */
    public static DSAPrivateKey loadDSAPrivateKeyFile(String uname){

        String filename = ClientConfig.getUserKeysPath()+"/"+uname+".pr";
        DSAPrivateKey prKey = null;

        FileInputStream fis = null;

        try {
            fis = new FileInputStream(filename);
            byte[] keyBytes = new byte[fis.available()];
            fis.read(keyBytes);

            KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");

            PKCS8EncodedKeySpec prKeySpec = new PKCS8EncodedKeySpec(keyBytes);

            prKey = (DSAPrivateKey) keyFactory.generatePrivate(prKeySpec);
        }
        catch (IOException e) {
            Logging.error(e.getMessage());
        }
        catch (NoSuchAlgorithmException e){
            Logging.error(e.getMessage());
        }
        catch (NoSuchProviderException e){
            Logging.error(e.getMessage());
        }
         catch(InvalidKeySpecException e){
            Logging.error(e.getMessage());
        }
        finally {
            CommonMessaging.close(fis);
        }

        return prKey;

    }

    /** Saves the given user's public key as encoded bytes.
     * It's the caller's responsibility to ensure that the
     * an existing saved public key can be overridden.
     *
     *@param uname the username whose public key is to be stored.
     *@param pubKey the public key to store for this user
     *@return whether the save succeeded
     */
    public static boolean saveDSAPublicKeyFile (String uname,
                                                DSAPublicKey pubKey) {
        byte[] keyBytes = pubKey.getEncoded();
        String filename = ClientConfig.getUserKeysPath()+"/"+uname+".pub";

        // make the parent dir structure if it doesn't exist
        File f = new File(filename);
        f.getParentFile().mkdirs();

        FileOutputStream fos = null;
        boolean success = false;
        try {
            fos = new FileOutputStream(filename);
            fos.write(keyBytes);
            success = true;
        }
        catch (IOException e) {
            Logging.error(e.getMessage());
        }
        finally {
            CommonMessaging.close(fos);
        }
        return success;
    }

    /** Saves the given user's private key to a file.
     * Generates an empty keystore if one doesn't exist.
     *
     *@param uname the username for which the key pair is to be saved
     *@param pr the private key to be saved
     *@return whether the private key was successfully saved or not
     */
    public static boolean saveDSAPrivateKeyFile(String uname,
                                                DSAPrivateKey pr) {

        byte[] keyBytes = pr.getEncoded();
        String filename = ClientConfig.getUserKeysPath()+"/"+uname+".pr";

        // make the parent dir structure if it doesn't exist
        File f = new File(filename);
        f.getParentFile().mkdirs();

        FileOutputStream fos = null;
        boolean success = false;
        try {
            fos = new FileOutputStream(filename);
            fos.write(keyBytes);
            success = true;
        }
        catch (IOException e) {
            Logging.error(e.getMessage());
        }
        finally {
            CommonMessaging.close(fos);
        }
        return success;

    }

    /** Saves the given key pair to disk. Generates an empty
     * keystore for the private key if one doesn't exist.
     *
     *@param uname the username for which the key pair is to be saved
     *@param kp the key pair to be saved
     *@return whether the save succeeded
     */
    public static boolean saveDSAKeyPairFile(String uname, KeyPair kp) {

        boolean success = false;

        if (saveDSAPrivateKeyFile(uname, (DSAPrivateKey)kp.getPrivate())) {
            success =
                saveDSAPublicKeyFile(uname, (DSAPublicKey)kp.getPublic());
        }

        return success;
    }

    /** Generates a DSA key pair for the client.
     *
     *@return the DSA key pair or null in case of an error
     *@deprecated Replaced with
     *{@link org.coniks.crypto.Keys#generateDSAKeyPair()}.
     */
    @Deprecated
    public static KeyPair generateDSAKeyPair(){

        KeyPairGenerator kg;

        try{
            kg = KeyPairGenerator.getInstance("DSA");
            kg.initialize(1024, new SecureRandom());
        }
        catch(NoSuchAlgorithmException e){
            Logging.error("DSA is not valid for some reason.");
            return null;
        }
        catch(InvalidParameterException e){
            Logging.error("DSA is not valid for some reason.");
            return null;
        }

        KeyPair kp = kg.generateKeyPair();

        return kp;

    }

} // ends KeyOps class
