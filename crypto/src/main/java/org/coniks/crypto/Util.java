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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** Implements all cryptographic utility functions for CONIKS.
 * Currently supported hash algorithms: SHA-256.
 *
 *@author Marcela S. Melara (melara@cs.princeton.edu)
 *@author Michael Rochlin
 */
public class Util {

     /** The size of a SHA-256 hash in bits.
     */
    public static final int HASH_SIZE_BITS =  256;

    /** The size of a SHA-256 hash in bytes.
     */
    public static final int HASH_SIZE_BYTES = HASH_SIZE_BITS/8;

    /** The supported hashing scheme.
     */
    public static final String HASH_ID = "SHA-256";

    /** Generates the cryptographic hash of {@code input}.
     * Current hashing algorithm: SHA-256.
     *
     *@return The hash as a {@code byte[]} or null in case of an error.
     */
    public static byte[] digest(byte[] input)
        throws NoSuchAlgorithmException {

        byte [] digest = null;
        try{
            MessageDigest md = MessageDigest.getInstance(HASH_ID);
            digest = md.digest(input);
            return digest;

        }
        // let's panic if an exception occurs
        finally {
            return digest;
        }
    }

}
