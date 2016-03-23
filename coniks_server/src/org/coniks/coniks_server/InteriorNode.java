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

import java.util.HashMap;
import java.io.Serializable;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;
import java.io.IOException;
import java.io.InvalidObjectException;

/** Represents an interior node in the CONIKS binary Merkle
 * prefix tree.
 *
 *@author Marcela S. Melara (melara@cs.princeton.edu)
 *@author Michael Rochlin (@marisbest2)
 */
public class InteriorNode extends TreeNode implements Serializable {
  
    byte[] leftHash;
    byte[] rightHash;
    boolean hasLeaf;

    /** Constructs an interior node with the given
     * parent tree node {@code p} and its level {@code lvl} 
     * within the tree.
     */
    public InteriorNode(TreeNode p, int lvl){
	
	this.left = null;
	this.right = null;
	this.parent = p;
	this.level = lvl;
	this.leftHash = null;
	this.rightHash = null;
        this.hasLeaf = false;
        this.name = ""; // for debugging

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

    /** Checks whether the interior node has at least one
     * leaf node child.
     *
     *@return {@code true} if the interior node has a leaf node child, 
     * {@code false} otherwise.
     */
    public boolean hasLeaf() {
        return this.hasLeaf;
    }

    /** Sets the left and right subtrees of the interior node to
     * tree nodes {@code l} and {@code r}, respectively.
     */
    public void setChildren(TreeNode l, TreeNode r){
	this.left = l;
	this.right = r;
    }

     /** Sets the hashes of the left and right subtrees of 
      * the interior node to {@code byte[]}s {@code l} and {@code r}, 
      * respectively.
     */
    public void setHashes(byte[] l, byte[] r){
	this.leftHash = l;
        this.rightHash= r;
    }

    /** Sets the parent of the interior node to tree node
     * {@code n}.
     */
    public void setParent(TreeNode n){
	this.parent = n;
    }

    /** Sets the {@code hasLeaf} flag to the boolean value given
     * by {@code l}.
     */
    public void setHasLeaf(boolean l) {
        this.hasLeaf = true;
    }

    /** Clones (i.e. duplicates) this interior node from the current
     * epoch {@code ep0} for the next epoch {@code ep1} with the
     * given {@code parent} tree node. It then recursively 
     * calls this function on the original interior node's two subtrees.
     *<p>
     * This function is called as part of the CONIKS Merkle tree
     * rebuilding process at the beginning of every epoch.
     *@return The cloned interior node.
     */
    public TreeNode clone(TreeNode parent, long ep0, long ep1){
	InteriorNode cloneN = new InteriorNode(null, null, parent, this.level, 
					       this.leftHash, this.rightHash, false);
	if (this.left != null)
	    cloneN.left = this.left.clone(cloneN, ep0, ep1);
	if (this.right != null)
	    cloneN.right = this.right.clone(cloneN, ep0, ep1);
	
	return cloneN;

    }

} // ends InteriorNode
