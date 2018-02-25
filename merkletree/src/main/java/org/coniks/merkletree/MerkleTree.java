/*
  Copyright (c) 2017, Princeton University.
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

import org.coniks.crypto.Digest;
import org.coniks.util.Convert;

public class MerkleTree {

    byte[] nonce;
    InteriorNode root;
    byte[] hash;


    public MerkleTree() {
        // TODO: catch the NoSuchAlgorithmExeption
        this.nonce = Digest.makeRand();
        this.root = new InteriorNode(null, 0);
        this.hash = null;
    }

    private MerkleTree(byte[] nonce) {
        this.nonce = nonce;
        this.root = null;
        this.hash = null;
    }

    /** Inserts or updates the value of the given index calculated from the
     * key to the tree. It generates a new commitment for the leaf node.
     * In the case of an update, the leaf node's value and commitment
     * are replaced with the new value and newly generated commitment.
     *
     *@param idx The index in the tree to set.
     *@param k The key used to compute the index.
     *@param v The value assocaited with the key.
     *@return -1 on an error, 0 otherwise.
     */
    public int set(byte[] idx, String k, byte[] v) {
        Commitment comm;
        try {
            comm = new Commitment(v);
        }
        catch(NoSuchAlgorithmException e) {
            // FIXME: return actual error code
            return -1;
        }

        UserLeafNode toAdd = new UserLeafNode(null, 0, k, v, idx, comm);
        this.insertNode(idx, toAdd);
        return 0;
    }

    // inserts a new user leaf node into the tree
    private void insertNode(byte[] idx, UserLeafNode toAdd){
        boolean [] indexBits = Convert.bytesToBits(idx);
        int depth = 0;
        TreeNode curNode = this.root;

        curNode.setName("root");
        int counter = 1;

        insertLoop:
        while(true){
            if (curNode instanceof UserLeafNode) {
                // reached a "bottom" of the tree.
                // add a new interior node and push the previous leaf down
                // then continue insertion
                UserLeafNode curNodeUL = (UserLeafNode) curNode;
                if (curNodeUL.parent == null){
                    throw new UnsupportedOperationException("parent is null!!");
                }

                // FIXME: Byte compare here
                if (curNodeUL.getIndex().equals(toAdd.getIndex())) {
                    // replace the value
                    toAdd.setParent(currentNodeUL.getParent());
                    toAdd.setLevel(currentNodeUL.getLevel());
                    currentNodeUL = toAdd;
                    return;
                }

                InteriorNode newInt = new InteriorNode(curNode.getParent(),
                                                       curNode.getLevel());

                // direction here is going to be false = left,
                //                               true = right
                boolean direction = Convert.getNthBit(currentNodeUL.getIndex(), depth);

                if (direction) {
                    newInt.setRight(curNodeUL);
                }
                else {
                    newInt.setLeft(curNodeUL);
                }
                curNodeUL.setLevel(depth + 1);
                curNode.setParent(newInt);

                if (newInt.getParent().getLeft() == curNode) {
                    newInt.parent.setLeft(newInt);
                }
                else {
                    newInt.parent.setRight(newInt);
                }
                curNode = newInt;
            }
            else (curNode instanceof InteriorNode) {
                InteriorNode curNodeI = (InteriorNode) curNode;
                // direction here is going to be false = left,
                //                               true = right
                boolean direction = indexBits[depth];

                if (direction) {
                    // mark right tree as needing hash recompute
                    curNodeI.resetRightHash();
                    if (curNodeI.getRight().isEmpty()){
                        curNodeI.setRight(toAdd);
                        toAdd.setLevel(depth+1);
                        toAdd.setParent(curNodeI);
                        break insertLoop;
                    }
                    else {
                        curNode = curNodeI.getRight();
                    }
                }
                else {
                    // mark left tree as needing hash recompute
                    curNodeI.resetLeftHash();
                    if (curNodeI.left.isEmpty()){
                        curNodeI.setLeft(toAdd);
                        toAdd.setLevel(depth+1);
                        toAdd.setParent(curNodeI);
                        break insertLoop;
                    }
                    else {
                        curNode = curNodeI.getLeft();
                    }
                }
                depth += 1;
            }
            else {
                throw new UnsupportedOperationException("Invalid tree");
            }
            curNode.setName("n"+counter);
            counter++;
        }
    }

    // Compute the hashes of the left and right subtrees
    // of the Merkle tree root
    // Wrapper for innerComputeHash
    private void recomputeHash() {
        this.hash = this.root.hash(this);
    }

    /** Duplicates the tree returning a fresh copy of the tree.
     *
     *@return a new copy of the cloned tree.
     */
    public MerkleTree clone() {
        // FIXME: this needs to create a full copy the nonce
        MerkleTree cloneM = new MerkleTree(this.nonce);
        cloneM.root = (InteriorNode)this.root.clone(null);

        // copy the hash into the new node
        byte[] hashBytes = new byte[this.hash.length];
        ByteBuffer arr = ByteBuffer.wrap(hashBytes);
        arr.put(this.hash);
        cloneM.hash = arr.array();

        return cloneM;
    }

}
