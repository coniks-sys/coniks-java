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

import org.coniks.coniks_common.C2SProtos.AuthPath;
import org.coniks.coniks_common.C2SProtos.*;
import org.coniks.coniks_common.UtilProtos.Hash;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.TreeMap;
import java.util.PriorityQueue;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.DSAPublicKey;
import java.nio.ByteBuffer;

import org.javatuples.*;

// TODO: Might want to separate this into more specialized classes
// for consistency checks vs internal ops

/** Implements all operations done by a CONIKS server
 * necessary for a CONIKS client to perform the consistency checks.
 * These include generating data binding proofs and signed tree roots (STR).
 * 
 *@author Marcela S. Melara (melara@cs.princeton.edu)
 *@author Michael Rochlin
 */
public class ServerOps{

    /** Generates the STR from the root node {@code rn}.
     *
     *@return The STR as a {@code byte[]}, or {@code null} in case of an error.
     */
    public static byte[] generateSTR(RootNode rn){
	byte[] rootBytes = ServerUtils.convertRootNode(rn);
        
        if (rootBytes == null) {
            return null;
        }
        
	return SignatureOps.sign(rootBytes);
    }
    
    /** Generates the authentication path protobuf message from the 
     * root node {@code root} to the user leaf node {@code uln}.
     *
     *@return The {@link org.coniks.coniks_common.C2SProtos.AuthPath} 
     * protobuf message or {@code null} upon failure.
     */
    public static AuthPath generateAuthPathProto(UserLeafNode uln, RootNode root){
    
        AuthPath.Builder authPath = AuthPath.newBuilder();

        //first take care of setting the UserLeafNode
        // TODO update for new uln version
        AuthPath.UserLeafNode.Builder ulnBuilder = AuthPath.UserLeafNode.newBuilder();
        ulnBuilder.setName(uln.getUsername());
        ulnBuilder.setPublickey(uln.getPublicKey());
        ulnBuilder.setEpochAdded(uln.getEpochAdded());
        ulnBuilder.setAllowsUnsignedKeychange(uln.allowsUnsignedKeychange());
        ulnBuilder.setAllowsPublicLookup(uln.allowsPublicLookups());
        ulnBuilder.addAllLookupIndex(ServerUtils.byteArrToIntList(uln.getIndex()));
        ulnBuilder.setEpochChanged(uln.getEpochChanged());
        if (uln.getSignature() != null)
            ulnBuilder.addAllSignature(ServerUtils.byteArrToIntList(uln.getSignature()));


        DSAPublicKeyProto.Builder dsaBuilder = DSAPublicKeyProto.newBuilder();
        DSAPublicKey dsa = uln.getChangeKey();
        if (dsa != null) {
            dsaBuilder.setP(dsa.getParams().getP().toString());
            dsaBuilder.setQ(dsa.getParams().getQ().toString());
            dsaBuilder.setG(dsa.getParams().getG().toString());
            dsaBuilder.setY(dsa.getY().toString()); // don't ask me why java is so inconsistent (mrochlin)

            ulnBuilder.setChangeKey(dsaBuilder.build());
        }
        if (uln.getLastMsg() != null)
            ulnBuilder.addAllLastMsg(ServerUtils.byteArrToIntList(uln.getLastMsg()));

        // book-keeping for interior nodes
        int numInteriors = 0;
        ArrayList<AuthPath.InteriorNode> interiorList = new ArrayList<AuthPath.InteriorNode>(); 
        
        // get the prefix from the key
	
	byte[] lookupIndex = ServerUtils.unameToIndex(uln.getUsername());

	byte[] prefix = ServerUtils.getPrefixBytes(lookupIndex);
        String prefixStr = ServerUtils.bytesToHex(prefix);

        // not worth doing this recursively
        int curOffset = 0;
    	TreeNode runner = root;

        while (!(runner instanceof UserLeafNode)) {

            // direction here is going to be false = left,
            //                               true = right
            boolean direction = ServerUtils.getNthBit(lookupIndex, curOffset);

            byte[] prunedChildHash = new byte[ServerUtils.HASH_SIZE_BYTES];

	    if (runner == null){
		System.out.println("Null runner" + curOffset);
	    }

            if (runner instanceof RootNode) {

                RootNode curNodeR = (RootNode) runner;

                AuthPath.RootNode.Builder rootBuilder = AuthPath.RootNode.newBuilder();
                 
                if(!direction){
                    prunedChildHash = curNodeR.getRightHash();
                    rootBuilder.setPrunedchild(AuthPath.PrunedChild.RIGHT);
                    runner = curNodeR.getLeft();
                }
                else {
                    prunedChildHash = curNodeR.getLeftHash();
                    rootBuilder.setPrunedchild(AuthPath.PrunedChild.LEFT);
                    runner = curNodeR.getRight();
                }

                Hash.Builder subtree = Hash.newBuilder();
                ArrayList<Integer> subTreeHashList = ServerUtils.byteArrToIntList(prunedChildHash);
                if(subTreeHashList.size() != ServerUtils.HASH_SIZE_BYTES){
                    System.out.println("Bad length of pruned child hash: "+subTreeHashList.size());
                    return null;
                }
                subtree.setLen(subTreeHashList.size());
                subtree.addAllHash(subTreeHashList);
                rootBuilder.setSubtree(subtree.build());
                
                byte[] prev = curNodeR.getPrev();
                Hash.Builder prevHash = Hash.newBuilder();
                ArrayList<Integer> prevHashList = ServerUtils.byteArrToIntList(prev);
                if(prevHashList.size() != ServerUtils.HASH_SIZE_BYTES){
                    System.out.println("Bad length of prev pointer hash: "+prevHashList.size());
                    return null;
                }
                prevHash.setLen(prevHashList.size());
                prevHash.addAllHash(prevHashList);
                rootBuilder.setPrev(prevHash.build());
                
                rootBuilder.setEpoch(curNodeR.getEpoch());
                authPath.setRoot(rootBuilder.build());
                
                curOffset++;
            }

            else {
                InteriorNode curNodeI = (InteriorNode) runner;
                
                AuthPath.InteriorNode.Builder inBuilder = AuthPath.InteriorNode.newBuilder();
               
                if(!direction){
                    prunedChildHash = curNodeI.getRightHash();
                    inBuilder.setPrunedchild(AuthPath.PrunedChild.RIGHT);
                    runner = curNodeI.getLeft();
                }                             
                else {
                    prunedChildHash = curNodeI.getLeftHash();
                    inBuilder.setPrunedchild(AuthPath.PrunedChild.LEFT);
                    runner = curNodeI.getRight();
                }
                Hash.Builder subtree = Hash.newBuilder();
                ArrayList<Integer> subTreeHashList = ServerUtils.byteArrToIntList(prunedChildHash);
                if(subTreeHashList.size() != ServerUtils.HASH_SIZE_BYTES){
                    System.out.println("Bad length of pruned child hash: "+subTreeHashList.size());
                    return null;
                }
                subtree.setLen(subTreeHashList.size());
                subtree.addAllHash(subTreeHashList);
                inBuilder.setSubtree(subtree.build());
                interiorList.add(0, inBuilder.build());
		
		if (runner == null){
		    System.out.println("such sadness...");
		}

                curOffset++;
                numInteriors++;
            }
  
        }

        ulnBuilder.setIntlevels(numInteriors);
        authPath.setLeaf(ulnBuilder.build());
        authPath.addAllInterior(interiorList);
        
        return authPath.build();
    }

    /** Generates a Hash protobuf message (e.g. included in the RootNode or
     * in the Commitment protobuf messages) with the given {@code hashBytes}.
     * The {@code name} inducates "whose" hash is being set up and is used for debugging.
     */
    private static Hash setupHashProto (byte[] hashBytes, String name) {
         ArrayList<Integer> hashList = ServerUtils.byteArrToIntList(hashBytes);
         
         if(hashList.size() != ServerUtils.HASH_SIZE_BYTES){
            System.out.println("Bad length of "+name+": "+hashList.size());
            return null;
        }

         Hash.Builder hash = Hash.newBuilder();
         hash.setLen(hashList.size());
         hash.addAllHash(hashList);

         return hash.build();

    }

    /** Builds a Merkle prefix tree consisting of only a root node
     * with the previous root hash {@code prevRootHash} for
     * epoch {@code ep}. This tree "skeleton"
     * is used when initializing the server's namespace.
     *
     *@return The {@link UserTreeBuilder} set up for building the intial
     * Merkle prefix tree.
     */
    public static UserTreeBuilder startBuildInitTree(byte[] prevRootHash,
						     long ep){

	UserTreeBuilder utb = UserTreeBuilder.getInstance();
	utb.createNewTree(null, prevRootHash, ep);
	return utb;

    }

    /** Builds the Merkle prefix tree for the first epoch after intializing
     * the server's namespace with the pending registrations in {@code pendingQ},
     * the initial epoch's root hash {@code initRootHash} and the new epoch
     * epoch {@code ep}. 
     *
     *@return The {@link RootNode} for the first epoch after initializing
     * the server's namespace or {@code null} in case of an error.
     */
    public static RootNode buildFirstEpochTree(
                                               PriorityQueue<Triplet<byte[], UserLeafNode, Operation>> pendingQ,
					       byte[] initRootHash,
					       long ep){

	UserTreeBuilder utb = UserTreeBuilder.getInstance();
	
        return utb.createNewTree(pendingQ, initRootHash, ep);

    }

    // update the history by adding all new users to the hash tree and updating the tree
    /** Builds the Merkle prefix tree for the next epoch after 
     * with the pending registrations in {@code pendingQ}, the current epoch's
     * root node {@code curRoot}, the current epoch {@code ep},
     * and the epoch interval {@code epInt}.
     *
     *@return The {@link RootNode} for the next epoch or {@code null} in case of an error.
     */
    public static RootNode buildNextEpochTree(
                                              PriorityQueue<Triplet<byte[], UserLeafNode, Operation>> pendingQ,
					      RootNode curRoot, 
					      long ep, int epInt){

	UserTreeBuilder utb = UserTreeBuilder.getInstance();
	
        // curRoot will become the next epoch's prev so we need to pass current root 
        // hash to buildTree()
        byte[] rootBytes = ServerUtils.convertRootNode(curRoot);
	return utb.copyExtendTree(curRoot, ServerUtils.hash(rootBytes), pendingQ, 
				     ep + epInt);
    }

} //ends ServerOps class
