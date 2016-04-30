/*
  Copyright (c) 2015, Princeton University.
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

package org.coniks.coniks_server;

import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.RSAPublicKeySpec;
import java.security.cert.CertificateException;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Scanner;
import java.io.PrintWriter;
import java.io.*;

/** Implements all operations involving encryption keys
 * that a CONIKS server must perform.
 * Current encryption/signing algorithm used: RSA with SHA-256.
 *
 *@author Marcela S. Melara (melara@cs.princeton.edu)
 */
public class KeyOps{

    /** Load <i>this</i> CONIKS server's private key from the keystore
     * indicated in the server's configuration.
     *
     *@return The server's private RSA key, or {@code null}
     * in the case of an Exception.
     */
    public static RSAPrivateKey loadSigningKey(){

        KeyStore ks = null;
        RSAPrivateKey myPrivateKey = null;

        try{
            ks = KeyStore.getInstance(KeyStore.getDefaultType());

            // get user password and file input stream
            char[] ks_password = ServerConfig.KEYSTORE_PWD.toCharArray();
            
            FileInputStream fis = null;
      
            fis = new FileInputStream(ServerConfig.KEYSTORE_PATH);
            ks.load(fis, ks_password);

            if(ks.isKeyEntry(ServerConfig.NAME)){
                KeyStore.ProtectionParameter protParam = 
                    new KeyStore.PasswordProtection(ks_password);

                KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
                    ks.getEntry(ServerConfig.NAME, protParam);
                myPrivateKey = (RSAPrivateKey)pkEntry.getPrivateKey();
            }
            else{
                throw new CertificateException();
            }
            fis.close();
            return myPrivateKey;
        }
        catch(IOException e){
            TimerLogger.error("KeyOps:loadSigningKey: Problem loading the keystore");
        }   
        catch(NoSuchAlgorithmException e){
            TimerLogger.error("KeyOps:loadSigningKey: Problem with integrity check algorithm");
        }
        catch(CertificateException e){
            TimerLogger.error("KeyOps:loadSigningKey: Problem with the cert(s) in keystore");
        }   
        catch(KeyStoreException e){
            TimerLogger.error("KeyOps:loadSigningKey: Problem getting Keystore instance");
        }
        catch(UnrecoverableEntryException e){
            TimerLogger.error("KeyOps:loadSigningKey: specified protParam were insufficient or invalid");
        }
        return null;
    }

     /** Load the given server {@code keyOwner}'s public key from the truststore
     * indicated in <i>this</i> server's configuration {@code config}.
     *
     *@return The {@code keyOwner}'s public RSA key, or {@code null} in 
     * the case of an Exception.
     */
    public static RSAPublicKey loadPublicKey(String keyOwner){

        KeyStore ks = null;
        RSAPublicKey publicKey = null;

        try{
            ks = KeyStore.getInstance(KeyStore.getDefaultType());

            char[] ts_password = ServerConfig.TRUSTSTORE_PWD.toCharArray();
            
            FileInputStream fis = null;
      
            fis = new FileInputStream(ServerConfig.TRUSTSTORE_PATH);
            ks.load(fis, ts_password);

            if(ks.isKeyEntry(keyOwner)){
                KeyStore.ProtectionParameter protParam = 
                    new KeyStore.PasswordProtection(ts_password);

                KeyStore.TrustedCertificateEntry pkEntry = (KeyStore.TrustedCertificateEntry)
                    ks.getEntry(keyOwner, protParam);
                publicKey = (RSAPublicKey)pkEntry.getTrustedCertificate().getPublicKey();
            }
            else{
                throw new CertificateException();
            }
            fis.close();
            return publicKey;
        }
        catch(IOException e){
            ServerLogger.error("KeyOps:loadPublicKey: Problem loading the keystore");
        }   
        catch(NoSuchAlgorithmException e){
            ServerLogger.error("KeyOps:loadPublicKey: Problem with integrity check algorithm");
        }
        catch(CertificateException e){
            ServerLogger.error("KeyOps:loadPublicKey: Problem with the cert(s) in keystore");
        }   
        catch(KeyStoreException e){
            ServerLogger.error("KeyOps:loadPublicKey: Problem getting Keystore instance");
        }
        catch(UnrecoverableEntryException e){
            ServerLogger.error("KeyOps:loadPublicKey: specified protParam were insufficient or invalid");
        }
        return null;
    }

} // ends KeyOps class
