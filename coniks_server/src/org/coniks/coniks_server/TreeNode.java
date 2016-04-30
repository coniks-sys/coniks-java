/*
  Copyright (c) 2015, Princeton University.
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

import java.io.Serializable;

/** Represents an generic tree node in the CONIKS binary Merkle
 * prefix tree.
 *
 *@author Marcela S. Melara (melara@cs.princeton.edu)
 */
public class TreeNode implements Serializable {

    TreeNode left; // the left child of the node
    TreeNode right; // the right child of the node 
    transient TreeNode parent; // the parent of the node
    int level; // indicates the level in the tree

    String name; // used for debugging

     /** Gets this tree node's left subtree.
     *
     *@return The left subtree as a {@link TreeNode}.
     */
    public TreeNode getLeft(){
	return left;
    }

    /** Gets this tree node's right subtree.
     *
     *@return The right subtree as a {@link TreeNode}.
     */
    public TreeNode getRight(){
	return right;
    }

    /** Gets this tree node's parent.
     *
     *@return The parent as a {@link TreeNode}. Will be {@code null}
     * if the tree node is a {@link RootNode}.
     */
    public TreeNode getParent(){
        return parent;
    }

    /** Gets this tree node's level in the Merkle tree.
     *
     *@return The level in the tree as an {@code int}.
     */
    public int getLevel(){
	return level;
    }

    /** Gets this tree node's name. 
     *<p>
     * This is used for debugging.
     *
     *@return The node's name as a {@code String}.
     */
    public String getName() {
        return name;
    }

    /** Sets this tree node's left subtree to {@code n}
     */
    public void setLeft(TreeNode n){
	this.left = n;
    }

    /** Sets this tree node's right subtree to {@code n}
     */
    public void setRight(TreeNode n){
	this.right = n;
    }

    /** Sets this tree node's parent to {@code n}
     */
    public void setParent(TreeNode n){
        this.parent = n;
    }

    /** Sets this tree node's level to {@code l}
     */
    public void setLevel(int l){
        this.level = l;
    }

    /** Sets this tree node's name to {@code name}
     */
    public void setName(String name) {
        this.name = name;
    }

    /** Cloning is not supported by generic {@link TreeNode}s,
     * only by their sub classes as these specify the more
     * specific data that needs to be duplicated when rebuilding
     * the CONIKS Merkle tree. Therefore each sub class of
     * TreeNode must specify its own cloning function.
     *
     *@throws An UnsupportedOperationException.
     */
    public TreeNode clone(TreeNode parent){
	throw new UnsupportedOperationException();
    }

} //ends TreeNode class
