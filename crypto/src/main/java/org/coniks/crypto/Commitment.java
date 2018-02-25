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

import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/** Implements a cryptographic commitment used in the CONIKS
 * Merkle tree to hide users' key information.
 *
 * {@code commit = hash(salt || blob)}
 *
 *@author Marcela S. Melara (melara@cs.princeton.edu)
 */
public class Commitment {

    private byte[] salt;
    private byte[] value;

    /** Generate a new commitment to protect CONIKS users' data.
     * The commitment consists of a random salt and the value.
     *
     *@throws a {@link java.security.NoSuchAlgorithmException}
     * if an error occurs in the underlying hash function.
     */
    public Commitment(byte[] data)
        throws NoSuchAlgorithmException {

        this.salt = Digest.makeRand();

        byte[] d = serialize(data);
        this.value = Digest.digest(d);
    }

    private Commitment(byte[] s, byte[] v) {
        this.salt = s;
        this.value = v;
    }

    /** Gets this commitment's random salt.
     *
     *@return the commitment salt
     */
    public byte[] getSalt() {
        return this.salt;
    }

    /** Gets this commitment's value.
     *
     *@return the commitment value as {@code hash(salt || blob)}
     */
    public byte[] getValue() {
        return this.value;
    }

    private byte[] serialize(byte[] data) {
        byte[] d = new byte[Digest.HASH_SIZE_BYTES+data.length];
        ByteBuffer buf = ByteBuffer.wrap(d);
        buf.put(this.salt);
        buf.put(data);

        return buf.array();
    }

    /** Verifies the commitment.
     *
     *@param opening the opening of the commitment to verify
     *@return {@code true} if the commitment is valid, {@code} false
     * otherwise.
     */
    public boolean verify(byte[] opening)
        throws NoSuchAlgorithmException {

        byte[] c = Digest.digest(serialize(opening));

        return Arrays.equals(c, this.value);

    }

    /** Duplicates the commitment.
     *
     *@return A fresh copy of the commitment.
     */
    public Commitment clone() {
        Commitment cloneC = new Commitment(this.salt, this.value);
        return cloneC;
    }

}
