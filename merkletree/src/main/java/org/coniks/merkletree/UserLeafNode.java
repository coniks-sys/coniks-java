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

package org.coniks.merkletree;

import java.io.Serializable;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;

// coniks-java imports
import org.coniks.crypto.Commitment;
import org.coniks.crypto.Digest;
import org.coniks.util.Convert;

/** Represents a leaf node containing a user's entry in the CONIKS key directory
 *  in the CONIKS binary Merkle prefix tree.
 *
 *@author Marcela S. Melara (melara@cs.princeton.edu)
 *@author Aaron Blankstein
 *@author Michael Rochlin
 */
public class UserLeafNode extends TreeNoe {

    public static final String LEAF_IDENTIFIER = "L";

    private String key;
    private byte[] value;
    private byte[] index;
    private Commitment commit;

    public UserLeafNode(String k, byte[] v, byte[] idx, Commitment comm) {
        this.parent = null;
        this.level = 0;
        this.key = k;
        this.value = v;
        this.index = idx;
        this.commit = comm;
    }

     /** Gets the {@link UserLeafNode}'s key.
     *
     *@return The key as a {@code String}.
     */
    protected String getKey(){
        return this.key;
    }

    /** Gets the {@link UserLeafNode}'s value.
     *
     *@return The value as a {@code byte[]}
     */
    protected byte[] getValue(){
        return this.value;
    }

    /** Gets the lookup index for the key in this {@link UserLeafNode}.
     *
     *@return The lookup index as a {@code byte[]}.
     */
    public byte[] getIndex() {
        return this.index;
    }

    /** Gets the {@link UserLeafNode}'s commitment.
     *
     *@return The commitment as a {@link org.coniks.crypto.Commitment}.
     */
    public Commitment getCommit() {
        return this.commit;
    }

    /** Clones (i.e. duplicates) this user leaf node with the
     * given {@code parent} tree node.
     *<p>
     * This function is called as part of the CONIKS Merkle tree
     * rebuilding process at the beginning of every epoch.
     *@return The cloned user leaf node.
     */
    public UserLeafNode clone(TreeNode parent){

        UserLeafNode cloneN = new UserLeafNode(this.key, this.value,
                                               this.index, this.Commitment);
        cloneN.parent = parent;
        cloneN.level = this.level;

        return cloneN;
    }

    protected byte[] serialize() {

        byte[] leafId = Convert.strToBytes(LEAF_IDENTIFIER);
        byte[] lvlBytes = Convert.intToBytes(this.level);
        byte[] commVal = this.commit.getValue();

        byte[] leafBytes = new byte[this.leafId.length+nonce.length+this.index.length+
                                    lvlBytes.length+commVal.length];

        ByteBuffer arr = ByteBuffer.wrap(leafBytes);
        arr.put(leafId);
        arr.put(nonce);
        arr.put(this.index);
        arr.put(lvlBytes);
        arr.put(commVal);

        return arr.array();
    }

} // ends UserLeafNode
