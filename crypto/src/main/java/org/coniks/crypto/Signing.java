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

package org.coniks.crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/** Implements all digital signature operations for CONIKS.
 * Currently supported algorithms: RSA with SHA-256 and DSA.
 *
 *@author Marcela S. Melara (melara@cs.princeton.edu)
 *@author Michael Rochlin
 */
public class Signing {

    /** The size of a 2048-bit RSA signature in bytes.
     */
    public static final int SIG_SIZE_BYTES = 256;

    /** Generate the RSA digital signature of {@code msg} using {@code key}.
     *
     *@param msg The message to be signed.
     *@param key The {@link java.security.interfaces.RSAPrivateKey} to use
     * for signing.
     *@return The {@code byte[]} containing the digital signature
     * of the {@code msg}, or null in case of an error.
     *@throws java.security.NoSuchAlgorithmException
     */
    public static byte[] rsaSign(RSAPrivateKey key, byte[] msg)
        throws NoSuchAlgorithmException {

        byte[] sig = null;
        try {
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(key, new SecureRandom());
            signer.update(msg);

            sig = signer.sign();
        }
        // let's panic if an exception occurs
        finally {
            return sig;
        }
    }

    /** Verify the RSA signature {@code sig} of {@code msg} using {@code pk}.
     *
     *@return {@code true} if the signature on the message is valid, {@code false}
     * otherwise.
     *@throws {@link java.security.NoSuchAlgorithmException NoSuchAlgorithmException}
     */
    public static boolean rsaVerify(RSAPublicKey pk, byte[] msg, byte[] sig)
        throws NoSuchAlgorithmException {

        boolean res = false;
        try {
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(pk);
            verifier.update(msg);

            res = verifier.verify(sig);
        }
        // let's panic if an exception occurs
        finally {
            return res;
        }
    }

    /** Generate the DSA digital signature of {@code msg} using {@code key}.
     *
     *@param msg The message to be signed.
     *@param key The {@link java.security.interfaces.DSAPrivateKey} to use
     * for signing.
     *@return The {@code byte[]} containing the digital signature
     * of the {@code msg}, or null in case of an error.
     *@throws
     *{@link java.security.NoSuchAlgorithmException NoSuchAlgorithmException}
     */
    public static byte[] dsaSign(DSAPrivateKey key, byte[] msg)
        throws NoSuchAlgorithmException {

        byte[] sig = null;
        try {
            Signature sigProcess = Signature.getInstance("DSA");
            sigProcess.initSign(key);
            sigProcess.update(msg);
            sig = sigProcess.sign();
        }
        // let's panic if an exception occurs
        finally {
            return sig;
        }
    }

    /** Verify the DSA signature {@code sig} of {@code msg} using {@code pk}.
     *
     *@return {@code true} if the signature on the message is valid,
     * {@code false}
     * otherwise.
     *@throws
     *{@link java.security.NoSuchAlgorithmException NoSuchAlgorithmException}
     */
    public static boolean dsaVerify(DSAPublicKey pk, byte[] msg, byte[] sig)
        throws NoSuchAlgorithmException {

        boolean res = false;
        try {
            Signature verifyalg = Signature.getInstance("DSA");
            verifyalg.initVerify(pk);
            verifyalg.update(msg);

            res = verifyalg.verify(sig);
        }
        // let's panic if an exception occurs
        finally {
            return res;
        }
    }

}
