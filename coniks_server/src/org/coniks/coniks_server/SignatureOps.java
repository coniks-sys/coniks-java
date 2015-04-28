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
import javax.crypto.*;

/** Implements all operations involving digital signatures
 * that a CONIKS server must perform.
 * Current encryption/signing algorithm used: RSA with SHA-256.
 *
 *@author Marcela S. Melara (melara@cs.princeton.edu)
 */
public class SignatureOps{

    private static ServerConfig CONFIG = null;

    /** Initialize the signature operations with the
     * server configuration {@code config}.
     */
    public static void initSignatureOps(ServerConfig config){
        CONFIG = config;
    }

    /** Digitally sign the {@code input}.
     *
     *@return The {@code byte[]} containing the digital signature
     * of the {@code input}.
     *@throws A RuntimeException if there is a problem with the private key
     * loaded from the server's keystore.
     */
    public static byte[] sign(byte[] input) {

        RSAPrivateKey MY_PRIV_KEY = KeyOps.loadSigningKey(CONFIG);

	byte[] signed = null;

        if(MY_PRIV_KEY == null){
	    throw new RuntimeException("borked pk?");
        }
	
	try{
	    Signature signer = Signature.getInstance("SHA256withRSA");
	    signer.initSign(MY_PRIV_KEY, new SecureRandom());
            signer.update(input);
	        
	    signed = signer.sign();
	    return signed;
	}
	catch(NoSuchAlgorithmException e){
	    TimerLogger.error("RSA is invalid for some reason.");
	}
	catch(InvalidKeyException e){
	    TimerLogger.error("The given key is invalid.");
	}
        catch(SignatureException e){
	    TimerLogger.error("The format of the input is invalid.");
	}
	
	return signed;
    }

    /** Verify a given server {@code keyOwner}'s digital signature {@code signature}
     * on the message {@code msg}.
     *
     *@return {@code true} if the signature on the message is valid, {@code false}
     * otherwise.
     */
    public static boolean verifySig(byte[] msg, byte[] signature, String keyOwner){

        RSAPublicKey pubKey = KeyOps.loadPublicKey(CONFIG, keyOwner);

	try{

	    Signature verifier = Signature.getInstance("SHA256withRSA");
	    verifier.initVerify(pubKey);
	    verifier.update(msg);
	    
	    return verifier.verify(signature);
	}
	catch(NoSuchAlgorithmException e){
	    TimerLogger.error("SHA256withRSA is invalid for some reason.");
	}
	catch(InvalidKeyException e){
	    TimerLogger.error("The given key is invalid.");
	}
	catch(SignatureException e){
	    TimerLogger.error("The format of the input is invalid: "+e.getMessage());
	}
	
	return false;

    }


} //ends SignatureOps class
