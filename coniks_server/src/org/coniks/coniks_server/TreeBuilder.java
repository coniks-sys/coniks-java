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

import java.util.PriorityQueue;
import java.security.KeyPair;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;

import org.javatuples.*;

/** Implements all operations necessary for building a CONIKS
 * Merkle prefix tree on the server. 
 * Current hashing algorithm used: SHA-256.
 *
 *@author Marcela S. Melara (melara@cs.princeton.edu)
 *@author Aaron Blankstein
 *@author Michael Rochlin
 */
public class TreeBuilder{
    
    private static int lastLevel;
    
    // inserts a new user leaf node into the tree
    private static void insertNode(byte[] key, UserLeafNode toAdd, RootNode root, Operation op){
        int curOffset = 0;
        // This code would be a lot more natural
        //   if our tries were byte-branching rather than bit-branching, but whatevs.
        
        toAdd.level = 0;
        TreeNode curNode = root;
        
        curNode.setName("root");
        int counter = 1;
        
        insertLoop:
        while(true){
            int arrayOffset = curOffset / 8;
            int bitOfByte = curOffset % 8;
            // 0 is left-most byte in string
            // 0 of left-most byte is the *left-most* bit of that byte. 
            toAdd.level++;
            
            if( curNode instanceof UserLeafNode ){
                // reached a "bottom" of the tree.
                // add a new interior node and push the previous leaf down
                // then continue insertion
                if (curNode.parent == null){
                    throw new UnsupportedOperationException("parent is null!!");
                }
                
                // TODO: Does this need to be moved?
                InteriorNode newInt = new InteriorNode(curNode.parent,
                                                       curNode.level);
                
                UserLeafNode curNodeUL = (UserLeafNode) curNode;
                if (curNodeUL.username.equals( toAdd.username )) {
                    if (op instanceof Register) {
                        // registration cant re-register the same name
                        throw new UnsupportedOperationException("Username of added node already exists!");
                    }
                    // must be some kind of key-change or flag change
                    else if (op instanceof KeyChange) {
                        if (((KeyChange)op).changeInfo(curNodeUL)) {
                            curNodeUL.setEpochChanged(op.epoch);
                            return;
                        }
                        else {
                            throw new UnsupportedOperationException("Failed to validate key change");
                        }
                    }
                    else {
                        // TODO
                        // Something got messed up or we added some functionality without implementing the change
                        throw new UnsupportedOperationException("Weird operation happened. Make sure you've added this functionality");
                    }
                }
                
                if (!(op instanceof Register)) {
                    throw new UnsupportedOperationException("Failed to make key-change!");
                }
                
                byte[] curNodeKey = ServerUtils.unameToIndex(curNodeUL.username);
                curNodeUL.setIndex(curNodeKey);
                // This is what's happening below:
                // int maskedBit = curNodeKey[(curOffset + 1)/8] & (1 << (7 - ((curOffset + 1) % 8)));
                int maskedBit = curNodeKey[arrayOffset] & (1 << (7 - bitOfByte));
                // direction here is going to be false = left,
                //                               true = right
                
                boolean direction = (maskedBit != 0);
                if (direction){
                    newInt.right = curNodeUL;
                }else{
                    newInt.left = curNodeUL;
                }
                curNode.level++;
                curNode.parent = newInt;
                
                if (newInt.parent.left == curNode) {
                    newInt.parent.left = newInt;
                }
                else {
                    newInt.parent.right = newInt;
                }
                curNode = newInt;
                toAdd.level--;                
            } 
            else {
                InteriorNode curNodeI = (InteriorNode) curNode;
                int maskedBit = key[arrayOffset] & (1 << (7 - bitOfByte));
                // direction here is going to be false = left,
                //                               true = right
                
                boolean direction = (maskedBit != 0);
                
                if(direction){
                    // mark right tree as needing hash recompute
                    curNodeI.rightHash = null;
                    if (curNodeI.right == null){
                        curNodeI.right = toAdd;
                        toAdd.parent = curNode;
                        break insertLoop;
                    }else{
                        curNode = curNodeI.right;
                    }
                }else{
                    // mark left tree as needing hash recompute
                    curNodeI.leftHash = null;
                    if (curNodeI.left == null){
                        curNodeI.left = toAdd;
                        toAdd.parent = curNode;
                        break insertLoop;
                    }else{
                        curNode = curNodeI.left;
                    }
                }
                curOffset++;
            }
            curNode.setName("n"+counter);
            counter++;
        }
        if (toAdd.level > lastLevel){
            lastLevel = toAdd.level;
        }
    }
    
    // Compute the hashes of the left and right subtrees
    // of the Merkle tree root
    // Wrapper for innerComputeHash
    private static void computeHashes(RootNode root){
        if (root.leftHash == null){
            root.leftHash = innerComputeHash(root.left);     
        }
        if (root.rightHash == null){
            root.rightHash = innerComputeHash(root.right);
        }
    }
    
    // this recursively computes the hash of the subtree specified
    // by curNode
    private static byte[] innerComputeHash(TreeNode curNode){
    	if(curNode == null) {
    	    return ServerUtils.hash(new byte[ServerUtils.HASH_SIZE_BYTES]);
    	}

    	if(curNode instanceof InteriorNode){
    	    InteriorNode curNodeI = (InteriorNode) curNode; 
    	    if(curNodeI.leftHash == null){
    		// compute left-side hash
    		curNodeI.leftHash = innerComputeHash(curNode.left);
    	    }
    	    if(curNodeI.rightHash == null){
    		// compute right-side hash
    		curNodeI.rightHash = innerComputeHash(curNode.right);
    	    }
            
    	    return ServerUtils.hash(ServerUtils.getInteriorNodeBytes(curNodeI));
    	}
        else{
    	    // assertion: must be user leaf node.
    	    UserLeafNode curNodeU = (UserLeafNode) curNode;
            return ServerUtils.hash(ServerUtils.getUserLeafNodeBytes(curNodeU));
    	}
    }
    
    /** Clones a Merkle prefix tree {@code prevRoot} and 
     * extends it with any new nodes in {@code pendingQ}.
     *
     *@return The {@link RootNode} for the next epoch's Merkle tree.
     */
    public static RootNode copyExtendTree(RootNode prevRoot,
                                          PriorityQueue<Triplet<byte[], UserLeafNode, Operation>> pendingQ){
        // clone old tree
        RootNode newRoot;
        if (prevRoot != null){
            newRoot = prevRoot.clone();
        }else{
            newRoot = new RootNode(null, null, 0);
        }
        
        if(pendingQ == null) {
            ServerLogger.error("Trying to extend using null pending queue");
            return null;
        }
        return extendTree(pendingQ, newRoot);
    }
    
    /** Inserts any new nodes in {@code pendingQ} ordered by the 24-bit prefix
     * of their lookup index into the Merkle tree, and recomputes all necessary 
     * hashes.
     *
     *@return The {@link RootNode} of the extended Merkle tree.
     */
    private static RootNode extendTree(
                                       PriorityQueue<Triplet<byte[], UserLeafNode, Operation>> pendingQ,
                                       RootNode root) {
        
        RootNode newRoot = root;
        
        byte[] prefix = null;
        
        int toInsert = pendingQ.size();
        
        Triplet<byte[], UserLeafNode, Operation> p = pendingQ.poll();
        while(p != null){
            // while we're handing the same prefix,
            // insert as normal
            byte[] index = p.getValue0();
            prefix = ServerUtils.getPrefixBytes(index);
            
            UserLeafNode toAdd = p.getValue1();
            Operation op = p.getValue2();
            
            insertNode(index, toAdd, newRoot, op);
            
            p = pendingQ.poll();
            
            toInsert--;
            
        }
        
        // recompute hashes
        computeHashes(newRoot);
        
        return newRoot;
    }
    
}
