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

package org.coniks.crypto;

import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.math.BigInteger;

/** Implements all encryption-key related operations that a
 * CONIKS server must perform.
 * Current encryption/signing algorithm used: RSA with SHA-256.
 *
 *@author Marcela S. Melara (melara@cs.princeton.edu)
 *@author Michael Rochlin
 */
public class Keys {

    /** Generates a DSA key pair.
     *
     *@return the DSA key pair or null in case of an error.
     */
    public static KeyPair generateDSAKeyPair()
        throws NoSuchAlgorithmException {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("DSA");
        gen.initialize(1024);

        KeyPair pair = gen.generateKeyPair();

        return pair;
    }

    /** Get the private key from the DSA key pair.
     *
     *@param kp The DSA KeyPair.
     *@return the DSA private key.
     */
    public static DSAPrivateKey getDSAPrivate(KeyPair kp) {
        return (DSAPrivateKey)kp.getPrivate();
    }

    /** Get the public key from the DSA key pair.
     *
     *@param kp The DSA KeyPair.
     *@return the DSA public key.
     */
    public static DSAPublicKey getDSAPublic(KeyPair kp) {
        return (DSAPublicKey)kp.getPublic();
    }

    /** Makes a {@link DSAPublicKey} from its {@code p}, {@code q},
     * {@code g} and {@code y} parameters.
     *
     *@return the DSAPublicKey, or {@code null} in case of an error.
     */
    public static DSAPublicKey getDSAPublicFromParams(BigInteger p, BigInteger q,
                                                          BigInteger g, BigInteger y) {

        DSAPublicKey pk = null;
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("DSA");
            KeySpec publicKeySpec = new DSAPublicKeySpec(y, p, q, g);
            pk = (DSAPublicKey)keyFactory.generatePublic(publicKeySpec);
        }
        // let's panic if an exception occurs
        finally {
            return pk;
        }
    }

    /** Generates an RSA key pair.
     *
     *@return the RSA key pair or null in case of an error.
     */
    public static KeyPair generateRSAKeyPair()
        throws NoSuchAlgorithmException {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);

        KeyPair pair = gen.generateKeyPair();

        return pair;
    }

    /** Get the private key from the RSA key pair.
     *
     *@param kp The RSA KeyPair.
     *@return the RSA private key.
     */
    public static RSAPrivateKey getRSAPrivate(KeyPair kp) {
        return (RSAPrivateKey)kp.getPrivate();
    }

    /** Get the public key from the RSA key pair.
     *
     *@param kp The RSA KeyPair.
     *@return the RSA public key.
     */
    public static RSAPublicKey getRSAPublic(KeyPair kp) {
        return (RSAPublicKey)kp.getPublic();
    }

}
