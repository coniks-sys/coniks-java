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
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.cert.CertificateException;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Scanner;
import java.io.PrintWriter;
import java.io.*;

import org.coniks.coniks_common.CommonMessaging;

/** Implements all operations involving encryption keys
 * that a CONIKS client must perform.
 *
 *@author Michael Rochlin
 */
public class KeyOps{

    /** Load <i>this</i> CONIKS client's private key from the keystore
     * indicated in the clients's ClientConfiguration {@code ClientConfig}.
     *
     *@return The client's private DSA key, or {@code null}
     * in the case of an Exception.
     */
    public static DSAPrivateKey loadSigningKey(String username){

        KeyStore ks = null;
        DSAPrivateKey myPrivateKey = null;

        try{
            ks = KeyStore.getInstance(KeyStore.getDefaultType());

            // get user password and file input stream
            char[] ks_password = ClientConfig.KEYSTORE_PWD.toCharArray();
            
            FileInputStream fis = null;
      
            fis = new FileInputStream(ClientConfig.KEYSTORE_PATH);
            ks.load(fis, ks_password);

            if(ks.isKeyEntry(username+"-priv")){
                KeyStore.ProtectionParameter protParam = 
                    new KeyStore.PasswordProtection(ks_password);

                KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
                    ks.getEntry(username+"-priv", protParam);
                myPrivateKey = (DSAPrivateKey)pkEntry.getPrivateKey();
            }
            else{
                throw new CertificateException();
            }
            fis.close();
            return myPrivateKey;
        }
        catch(IOException e){
            ClientLogger.error("KeyOps:loadSigningKey: Problem loading the keystore");
        }   
        catch(NoSuchAlgorithmException e){
            ClientLogger.error("KeyOps:loadSigningKey: Problem with integrity check algorithm");
        }
        catch(CertificateException e){
            ClientLogger.error("KeyOps:loadSigningKey: Problem with the cert(s) in keystore");
        }   
        catch(KeyStoreException e){
            ClientLogger.error("KeyOps:loadSigningKey: Problem getting Keystore instance");
        }
        catch(UnrecoverableEntryException e){
            ClientLogger.error("KeyOps:loadSigningKey: specified protParam were insufficient or invalid");
        }
        return null;
    }

    /** Generates a DSA key pair for the client.
     *
     *@return the DSA key pair or null in case of an error
     */
    public static KeyPair generateDSAKeyPair(){

        KeyPairGenerator kg;
        
        try{
            kg = KeyPairGenerator.getInstance("DSA");
            kg.initialize(1024, new SecureRandom());
        }
        catch(NoSuchAlgorithmException e){
            ClientLogger.error("DSA is not valid for some reason.");
            return null;
        }
        catch(InvalidParameterException e){
            ClientLogger.error("DSA is not valid for some reason.");
            return null;
        }

        KeyPair kp = kg.generateKeyPair();

        return kp;

    } //ends generateKeyPair()

    /** Saves the given key pair to the keystore. Generates an empty
     * keystore if one doesn't exist.
     *
     *@param kp the key pair to be saved
     */
    public static void saveKeyPair(String username, KeyPair kp) {
        File ksFile = new File(ClientConfig.KEYSTORE_PATH);

        KeyStore ks;

        // get user password
        char[] ksPassword = ClientConfig.KEYSTORE_PWD.toCharArray();;

        // File streams
        FileInputStream fis = null;
        FileOutputStream fos = null;

        // load the keystore
        try { 
            ks = KeyStore.getInstance(KeyStore.getDefaultType());

            // generate an empty keystore if it doesn't exist
            if (!ksFile.exists()) {            
                ks.load(fis, ksPassword);
            }
            else {
                fis = new FileInputStream(ksFile);
                ks.load(fis, ksPassword);
            }

            // save the private key
            KeyStore.PrivateKeyEntry privKeyEntry = new KeyStore.PrivateKeyEntry(kp.getPrivate(), null);

            KeyStore.ProtectionParameter protParam = 
                new KeyStore.PasswordProtection(ksPassword);

            // for now, let's not store another entry if this client already has one
            if (ks.getEntry(username+"-priv", protParam) == null) {
                ks.setEntry(username+"-priv", privKeyEntry, protParam);
                
                fos = new FileOutputStream(ksFile);
                
                ks.store(fos, ksPassword);
            }
        }
        catch(IOException e){
            ClientLogger.error(e.getMessage());
        }   
        catch(NoSuchAlgorithmException e){
            ClientLogger.error(e.getMessage());
        }
        catch(CertificateException e){
            ClientLogger.error(e.getMessage());
        }
        catch(KeyStoreException e) {
            ClientLogger.error(e.getMessage());
        }
        catch(UnrecoverableEntryException e) {
            ClientLogger.error(e.getMessage());
        }
        finally {
            CommonMessaging.close(fis);
            CommonMessaging.close(fos);
        }
     
    }

    /** This is a really bad function that takes a string we assume contains a DSA key in 
        a poorly designed format, and returns the parameters if it can */
    public static BigInteger[] getDSAParamsFromString(String s) {
        // This method assumes that the key is written in a particular format
        // If it isn't, it will just return null
        // This should really only be used in testing
        try {
            int startp = s.indexOf('p');
            if (startp < 0) return null;
            int poundsym = s.indexOf('#', startp);
            if (poundsym < 0) return null;
            int poundsymend = s.indexOf('#', poundsym);
            if (poundsymend < 0) return null;
            int name_end = s.indexOf("-", poundsym);
            if (name_end > 0) poundsym = name_end;
            String ps = s.substring(poundsym + 1, poundsymend);
            BigInteger p = new BigInteger(ps);

            int startq = s.indexOf('q', poundsymend);
            if (startq < 0) return null;
            poundsym = s.indexOf('#', startq);
            if (poundsym < 0) return null;
            poundsymend = s.indexOf('#', poundsym);
            if (poundsymend < 0) return null;
            String qs = s.substring(poundsym + 1, poundsymend);
            BigInteger q = new BigInteger(qs);

            int startg = s.indexOf('g', poundsymend);
            if (startg < 0) return null;
            poundsym = s.indexOf('#', startg);
            if (poundsym < 0) return null;
            poundsymend = s.indexOf('#', poundsym);
            if (poundsymend < 0) return null;
            String gs = s.substring(poundsym + 1, poundsymend);
            BigInteger g = new BigInteger(gs);

            int starty = s.indexOf('y', poundsymend);
            if (starty < 0) return null;
            poundsym = s.indexOf('#', starty);
            if (poundsym < 0) return null;
            poundsymend = s.indexOf("))", poundsym);
            if (poundsymend < 0) return null;
            String ys = s.substring(poundsym + 1, poundsymend);
            BigInteger y = new BigInteger(ys);

            BigInteger[] arr = {p, q, g, y};
            return arr;
        }
        catch (IndexOutOfBoundsException e) {
            return null;
        }
        catch (NumberFormatException e) {
            return null;
        }
    }

} // ends KeyOps class
