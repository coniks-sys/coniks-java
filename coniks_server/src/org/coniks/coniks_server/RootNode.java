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

package org.coniks.coniks_server;

/** Represents a root node in the CONIKS binary Merkle
 * prefix tree.
 *
 *@author Marcela S. Melara (melara@cs.princeton.edu)
 */
public class RootNode extends InteriorNode{

    byte[] prev; // serves as prev pointer to last epoch's root node
    long epoch;

    // blanks: at the moment we are going to hard code this as a "binary" trie.
    /** Specifies the branching factor of the CONIKS Merkle prefix tree.
     * CONIKS is currently uses a binary tree.
     */
    public final int digitSize = 2;

    /** Constructs a root node specified
     * with left and right subtrees {@code l} and {@code r},
     * the hash of the previous epoch's tree root {@code prev}, 
     * the level in tree {@code lvl}, and the epoch {@code ep}
     * for which this root is valid.
     *<p>
     * This is the constructor used in 
     * {@link UserTreeBuilder#copyExtendTree(RootNode, byte[], PriorityQueue<Pair<byte[], UserLeafNode>>, long)}.
     */
    public RootNode(TreeNode l, TreeNode r, int lvl, byte[] prev, long ep){
	this(l, r, lvl, prev, ep, null, null);
    }

    /** Constructs a root node specified
     * with left and right subtrees {@code l} and {@code r}
     * and their corresponding hashes {@code lh} and {@code rh},
     * the hash of the previous epoch's tree root {@code prev}, 
     * the level in tree {@code lvl}, and the epoch {@code ep}
     * for which this root is valid.
     *<p>
     * This is the constructor used {@link RootNode#clone(long, long)}.
     */
    public RootNode(TreeNode l, TreeNode r, int lvl, byte[] prev, long ep, 
		    byte[] lh, byte[] rh){
	super(l, r, null, lvl, lh, rh, false);
	
	this.prev = prev;
	this.epoch = ep;	
	
    }

    /** Gets the hash of the previous epoch's tree root.
     *
     *@return The hash of the previous epoch's tree root as a {@code byte[]} (it should
     * not be {@code null}).
     */
    public byte[] getPrev(){
	return this.prev;
    }

    /** Gets the epoch for which this root node is valid.
     *
     *@return The epoch for this root node.
     */
    public long getEpoch(){
	return this.epoch;
    }

    /** Sets this root node's left and right subtrees to
     * tree nodes {@code l} and {@code r}.
     */
   public void setChildren(TreeNode l, TreeNode r){
	this.left = l;
	this.right = r;
    }

    /** Sets the hashes of left and right
     * subtrees of this root node to the {@code byte[]}s {@code l} 
     *and {@code r}.
     */
    public void setHashes(byte[] l, byte[] r){
	this.leftHash = l;
        this.rightHash= r;
    }

     /** Clones (i.e. duplicates) this root node from the current
     * epoch {@code ep0} for the next epoch {@code ep1} with the. 
     * It then recursively 
     * calls this function on the original root node's two subtrees.
     *<p>
     * This function is called as part of the CONIKS Merkle tree
     * rebuilding process at the beginning of every epoch.
     *@return The cloned root node.
     */
    public RootNode clone(long epoch0, long epoch1){
        // the epoch will be reset in UserTreeBuilder.
	RootNode cloneN = new RootNode(null, null, this.level, 
				       null, -1, leftHash, rightHash);
	if (this.left != null)
	    cloneN.left = this.left.clone(cloneN, epoch0, epoch1);
	if (this.right != null)
	    cloneN.right = this.right.clone(cloneN, epoch0, epoch1);
	
	return cloneN;
    }

} // ends RootNode
