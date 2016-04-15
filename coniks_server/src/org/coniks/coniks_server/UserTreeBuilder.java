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

import java.nio.charset.Charset;

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
 *@author Michael Rochlin
 */
public class UserTreeBuilder{
    
    private int lastLevel;
    private RootNode out;
    private long prevEpoch, epoch;

    /** Clears some temporary variables set
     * during a previous call to 
     * {@link UserTreeBuilder#createNewTree(PriorityQueue<Pair<byte[], UserLeafNode>>, byte[], long)}.
     */
    public void clearTemps(){
        out = null;
    }
    
    private UserTreeBuilder(){
        lastLevel = 0;
    }

    /** Generates a single instance of the user tree builder.
     *
     *@return A new user tree builder.
     */
    public static UserTreeBuilder getInstance(){
        return new UserTreeBuilder();
    }
    
    private void insertNode(byte[] key, UserLeafNode toAdd, RootNode root, Operation op){
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
                            curNodeUL.setEpochChanged(epoch);
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
                // msm: why is this next line here?
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
    	if(curNode == null){
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
    	    return ServerUtils.hash(ServerUtils.convertInteriorNode(curNodeI));
    	}else{
    	    // assertion: must be user leaf node.
    	    UserLeafNode curNodeU = (UserLeafNode) curNode;
    	    return ServerUtils.hash(ServerUtils.convertUserLeafNode(curNodeU));
    	}
    }

    /** Clones the previous epoch's tree {@code prevRoot} and 
     * extends it with any new nodes in {@code pendingQ} 
     * to add for the next epoch {@code epoch}.
     *<p> 
     * This is a useful wrapper for 
     * {@link UserTreeBuilder#extendTree(PriorityQueue<Pair<byte[], UserLeafNode>>)}.
     *
     *@return The {@link RootNode} for the next epoch's Merkle tree.
     */
    public RootNode copyExtendTree(RootNode prevRoot,
                                   byte[] prevRootHash,
                                   PriorityQueue<Triplet<byte[], UserLeafNode, Operation>> pendingQ, 
                                   long epoch){
        // clone old tree
        RootNode out;
        long prevEpoch;
        if (prevRoot != null){
            prevEpoch = prevRoot.epoch;
            out = (prevRoot.clone(prevEpoch, epoch));
        }else{
            out = new RootNode(null, null, 0, null, 0);
            prevEpoch = -1;
        }
        out.prev = prevRootHash;
        
        this.prevEpoch = prevEpoch;
        this.epoch = epoch;
        this.out = out;
        
        if(pendingQ == null)
            return null;
        return extendTree(pendingQ);
    }

    /** Inserts any new nodes in {@code pendingQ} ordered by the 24-bit prefix
     * of their lookup index into the Merkle tree, and recomputes all necessary 
     * hashes.
     *
     *@return The {@link RootNode} of the extended Merkle tree.
     */
    public RootNode extendTree(PriorityQueue<Triplet<byte[], UserLeafNode, Operation>> pendingQ){        
        // set up new root
        out.epoch = epoch;
        
        // insert nodes
        // record the prefix for each index and compare to the prefix of the
        // previous node added
        byte[] prefix = null;
        byte[] prevPrefix = null;        
        
        int prevPrefixLevel = 0;
        int insCount = 0;
        // need to insert all nodes with the same prefix into the correct prefix subtree
        
        int toInsert = pendingQ.size();
        
        Triplet<byte[], UserLeafNode, Operation> p = pendingQ.poll();
        while(p != null){
            // while we're handing the same prefix,
            // insert as normal
            byte[] index = p.getValue0();
            prefix = ServerUtils.getPrefixBytes(index);
            
            UserLeafNode toAdd = p.getValue1();
            Operation op = p.getValue2();
            
            insertNode(index, toAdd, out, op);
            
            if (prevPrefixLevel < toAdd.getLevel())
                prevPrefixLevel = toAdd.getLevel(); 
            

            prevPrefix = prefix;
            
            p = pendingQ.poll();
            
        }
        
        // recompute hashes
        computeHashes(out);
        
        return out;
    }
    
    /** Creates a completely new Merkle tree with any nodes in {@code pendingQ},
     * and with the previous epoch's root hash {@code prevRootHash} for the new epoch
     * {@code epoch}.
     *
     *@return The {@link RootNode} of the new Merkle tree.
     */
    public RootNode createNewTree(PriorityQueue<Triplet<byte[], UserLeafNode, Operation>> pendingQ,
                                  byte[] prevRootHash, long epoch){
        return copyExtendTree(null, prevRootHash, pendingQ, epoch);

    }
    
}
