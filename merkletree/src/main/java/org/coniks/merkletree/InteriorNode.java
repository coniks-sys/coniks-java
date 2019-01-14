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

import java.nio.ByteBuffer;

// coniks-java imports
import org.coniks.crypto.Digest;

/** Represents an interior node in the CONIKS binary Merkle
 * prefix tree.
 *
 *@author Marcela S. Melara (melara@cs.princeton.edu)
 *@author Aaron Blankstein
 *@author Michael Rochlin
 */
public class InteriorNode extends TreeNode
    implements MerkleNode {

    private MerkleNode left; // the left child of the node
    private MerkleNode right; // the right child of the node
    private byte[] leftHash;
    private byte[] rightHash;

    /** Constructs an interior node with the given
     * parent tree node {@code p} and its level {@code lvl}
     * within the tree.
     */
    public InteriorNode(MerkleNode p, int lvl){
        super(p, lvl);
        this.left = new EmptyNode(p, lvl);
        this.right = new EmptyNode(p, lvl);
        this.leftHash = null;
        this.rightHash = null;
        this.setName(""); // for debugging
    }

    /** Protected constructor for an interior node specified
     * with left and right subtrees {@code l} and {@code r}
     * and their corresponding hashes {@code lh} and {@code rh},
     * the parent tree node {@code p}, level in tree {@code lvl}, and
     * the flag {@code hasLeaf} indicating whether the interior node
     * has at least one leaf node as a child.
     */
    private InteriorNode(MerkleNode p, int lvl, MerkleNode l, MerkleNode r,
                         byte[] lh, byte[] rh) {
        super(p, lvl);
        this.left = l;
        this.right = r;
        this.leftHash = lh;
        this.rightHash = rh;
        this.name = ""; // for debugging
    }

    /** Gets this tree node's left subtree.
     *
     *@return The left subtree as a {@link MerkleNode}.
     */
    public MerkleNode getLeft(){
        return left;
    }

    /** Gets this tree node's right subtree.
     *
     *@return The right subtree as a {@link MerkleNode}.
     */
    public MerkleNode getRight(){
        return right;
    }

    /** Sets this tree node's left subtree.
     *
     *@param n The MerkleNode to set as the left subtree.
     */
    public void setLeft(MerkleNode n){
        this.left = n;
    }

    /** Sets this tree node's right subtree.
     *
     *@param n The MerkleNode to set as the right subtree.
     */
    public void setRight(MerkleNode n){
        this.right = n;
    }

    /** Gets the hash of the left subtree.
     *
     *@return The hash of the left subtree as a {@code byte[]} (it
     * may be {@code null}).
     */
    public byte[] getLeftHash(){
        return this.leftHash;
    }

    /** Gets the hash of the right subtree.
     *
     *@return The hash of the right subtree as a {@code byte[]} (it
     * may be {@code null}).
     */
    public byte[] getRightHash(){
        return this.rightHash;
    }

    /** Sets the hash of the left subtree to {@code null}.
     */
    public void resetLeftHash(){
        this.leftHash = null;
    }

    /** Sets the hash of the right subtree to {@code null}.
     */
    public void getRightHash(){
        this.rightHash = null;
    }

    /** Clones (i.e. duplicates) this interior node with the
     * given {@code parent} tree node. It then recursively
     * calls this function on the original interior node's two subtrees.
     *<p>
     * This function is called as part of the CONIKS Merkle tree
     * rebuilding process at the beginning of every epoch.
     *@return The cloned interior node.
     */
    public MerkleNode clone(InteriorNode parent){
        // FIXME: this needs to do a full copy of the hashes
        InteriorNode cloneN = new InteriorNode(parent, this.level,
                                               null, null,
                                               this.leftHash,
                                               this.rightHash, false);
        if (this.left == null || this.right == null) {
            // FIXME
            throw new UnsupportedOperationException("child is null!");
        }
        cloneN.left = this.left.clone(cloneN);
        cloneN.right = this.right.clone(cloneN);
        return cloneN;
    }

    /** Serializes the left and right hashes of this interior node
     * into a {@code byte[]}.
     *
     *@return the serialized interior node
     */
    public byte[] serialize(){
        byte[] nodeBytes = new byte[this.leftHash.length+
                                    this.rightHash.length];

        ByteBuffer arr = ByteBuffer.wrap(nodeBytes);
        arr.put(this.leftHash);
        arr.put(this.rightHash);

        return arr.array();
    }

    /** Hashes this interior and its children recursively.
     *
     *@return the hash of this interior node and its children
     */
    public byte[] hash(MerkleTree tree) {
        if (this.leftHash == null) {
            this.leftHash = this.left.hash(tree);
        }
        if (this.rightHash == null) {
            this.rightHash = this.right.hash(tree);
        }

        byte[] nodeBytes = new byte[this.leftHash.length+
                                    this.rightHash.length];
        ByteBuffer arr = ByteBuffer.wrap(nodeBytes);
        arr.put(this.leftHash);
        arr.put(this.rightHash);

        return Digest.digest(arr.array());
    }

    public boolean isEmpty() {
        return false;
    }

} // ends InteriorNode
