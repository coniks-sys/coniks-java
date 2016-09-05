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
import java.security.KeyPair;
import java.security.spec.*;
import java.security.interfaces.*;
import javax.crypto.*;
import java.math.BigInteger;

// coniks-java import
import org.coniks.util.Logging;

/** Implements all operations involving digital signatures
 * that a CONIKS client must perform.
 *
 *@author Michael Rochlin
 */
public class SignatureOps{

    /** Verifies {@code msg} and the {@code sig} using the DSA PublicKey
     * {@code pk}
     *
     *@return {@code true} if the signature is valid,
     * {@code false} otherwise.
     *@deprecated Replaced with
     *{@link org.coniks.crypto.Signing#dsaVerify(DSAPublicKey, byte[], byte[])}.
     */
    @Deprecated
    public static boolean verifySigFromDSA(byte[] msg, byte[] sig,
                                           PublicKey pk) {
        try {
            Signature verifyalg = Signature.getInstance("DSA");
            verifyalg.initVerify(pk);
            verifyalg.update(msg);
            if (!verifyalg.verify(sig)) {
                Logging.error("Failed to validate signature");
                return false;
            }
            return true;
        }
        catch(NoSuchAlgorithmException e){
            Logging.error("DSA is invalid for some reason.");
        }
        catch(InvalidKeyException e){
            Logging.error("The given key is invalid.");
        }
        catch(SignatureException e){
            Logging.error("The format of the input is invalid: "+e.getMessage());
        }
        return false;
    }

    /** Signs {@code msg} using DSAPrivateKey {@code prk}
     *
     *@return the signature or null on an error
     *@deprecated Replaced with {@link org.coniks.crypto.Signing#dsaSign(DSAPrivateKey, byte[])}.
     */
    @Deprecated
    public static byte[] signDSA(byte[] msg, DSAPrivateKey prk) throws InvalidKeyException {
        if (prk == null) {
            Logging.error("The given key is invalid.");
        }
        else {
            try {
                Signature sigProcess = Signature.getInstance("DSA");
                sigProcess.initSign(prk);
                sigProcess.update(msg);
                return sigProcess.sign();
            }
            catch(NoSuchAlgorithmException e){
                Logging.error("DSA is invalid for some reason.");
            }
            catch(InvalidKeyException e){
                Logging.error("The given key is invalid.");
            }
            catch(SignatureException e){
                Logging.error("The format of the input is invalid: "+e.getMessage());
            }
        }
            return null;
    }


}
