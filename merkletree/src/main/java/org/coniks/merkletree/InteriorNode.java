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
public class InteriorNode extends TreeNode {

    protected TreeNode leftChild; // the left child of the node
    protected TreeNode rightChild; // the right child of the node
    protected byte[] leftHash;
    protected byte[] rightHash;

    /** Constructs an interior node with the given
     * parent tree node {@code p} and its level {@code lvl}
     * within the tree.
     */
    public InteriorNode(TreeNode p, int lvl){
        super(p, lvl);
        this.leftChild = null;
        this.rightChild = null;
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
    protected InteriorNode(TreeNode l, TreeNode r, TreeNode p, int lvl, byte[] lh, byte[] rh,
                           boolean hasLeaf){
        this.left = l;
        this.right = r;
        this.parent = p;
        this.level = lvl;
        this.leftHash = lh;
        this.rightHash = rh;
        this.hasLeaf = hasLeaf;
        this.name = ""; // for debugging
    }

    /** Gets this tree node's left subtree.
     *
     *@return The left subtree as a {@link TreeNode}.
     */
    public TreeNode getLeftChild(){
        return leftChild;
    }

    /** Gets this tree node's right subtree.
     *
     *@return The right subtree as a {@link TreeNode}.
     */
    public TreeNode getRightChild(){
        return rightChild;
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

    /** Clones (i.e. duplicates) this interior node with the
     * given {@code parent} tree node. It then recursively
     * calls this function on the original interior node's two subtrees.
     *<p>
     * This function is called as part of the CONIKS Merkle tree
     * rebuilding process at the beginning of every epoch.
     *@return The cloned interior node.
     */
    public TreeNode clone(TreeNode parent){
        InteriorNode cloneN = new InteriorNode(null, null, parent, this.level,
                                               this.leftHash, this.rightHash, false);
        if (this.left != null)
            cloneN.left = this.left.clone(cloneN);
        if (this.right != null)
            cloneN.right = this.right.clone(cloneN);

        return cloneN;

    }

    /** Serializes the left and right hashes of this interior node
     * into a {@code byte[]}.
     *
     *@return the serialized interior node
     */
    protected byte[] serialize(){
        byte[] nodeBytes = new byte[this.leftHash.length+this.rightHash.length];

        ByteBuffer arr = ByteBuffer.wrap(nodeBytes);
        arr.put(this.leftHash);
        arr.put(this.rightHash);

        return arr.array();
    }

    /** Hashes this interior and its children recursively.
     *
     *@return the hash of this interior node and its children
     */
    public byte[] hash() {
        if (this.leftHash == null) {
            this.leftHash = this.leftChild.hash();
        }
        if (this.rightHash == null) {
            this.rightHash = this.rightChild.hash();
        }
        return Digest.digest(this.serialize());
    }

} // ends InteriorNode
