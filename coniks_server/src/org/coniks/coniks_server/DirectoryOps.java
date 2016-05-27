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

package org.coniks.coniks_server;

import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.DSAParams;
import java.util.PriorityQueue;

import org.javatuples.*;

/** Implements the high-level key directory-related operations performed by a
 * CONIKS server.
 *
 *@author Marcela S. Melara (melara@cs.princeton.edu)
 *@author Michael Rochlin
 */
public class DirectoryOps {

    // keeps all the operations pending to be inserted into the directory
    private static PriorityQueue<Triplet<byte[], UserLeafNode, Operation>> pendingQueue =
        new PriorityQueue<Triplet<byte[], UserLeafNode, Operation>>( 
                                                                    16384, new ServerUtils.PrefixComparator());;   

    // this is a counter to be used to sort the uln changes so they happen in-order for the same person
    private static long ulnCounter = 0;

    /** Registers a new name-to-key mapping in the key directory. Adds this registration
     * operation to the queue of pending operations, which are handled once per epoch.
     *
     *@param uname the username to register
     *@param pk the public key data to map to the registered name
     *@param ck the DSA public key used for key changes
     *@param allowsUnsignedChanges flag indicating the user's key change policy
     *@param allowsPublicVisibility flag indicating the user's key visibility policy
     */
    public static synchronized void register(String uname, String pk, DSAPublicKey ck,
                                             boolean allowsUnsignedChanges, boolean allowsPublicVisibility){            
        byte[] index = ServerUtils.unameToIndex(uname);
        UserLeafNode uln = new UserLeafNode(uname, pk, ServerHistory.nextEpoch(), 0,
                                            allowsUnsignedChanges, allowsPublicVisibility, ck, index);
        pendingQueue.add(Triplet.with(index, uln, (Operation)new Register()));
    }

    /** Changes an existing name-to-key mapping in the key directory. Adds this mapping change
     * operation to the queue of pending operations, which are handled once per epoch.
     *
     *@param uname the username
     *@param newKey the new public key data to be mapped to the registered name
     *@param ck the DSA public key used for key changes
     *@param allowsUnsignedChanges flag indicating the user's key change policy
     *@param allowsPublicVisibility flag indicating the user's key visibility policy
     *@param msg the mapping change message required for signed changes
     *@param sig the signature on {@code msg} required for signed changes
     */
    public static synchronized void mappingChange(String uname, String newKey, DSAPublicKey ck, 
                                                  boolean allowsUnsignedChanges, boolean allowsPublicVisibility,
                                                  byte[] msg, byte[] sig) {
        byte[] index = ServerUtils.unameToIndex(uname);
        UserLeafNode uln = new UserLeafNode(uname, newKey, ServerHistory.nextEpoch(), 0,
                                            allowsUnsignedChanges, allowsPublicVisibility, ck, index);
        KeyChange change = new KeyChange(newKey, ck, allowsUnsignedChanges, allowsPublicVisibility,
                                         msg, sig, ServerHistory.nextEpoch(), 0);
        pendingQueue.add(Triplet.with(index, uln, (Operation)change));
    }

    /** Searches for the username {@code uname} in the current version of the
     * key directory.
     *
     *@return the user's entry in the directory or null if the name can't be found.
     */
    public static synchronized UserLeafNode findUser(String uname) {
        RootNode root = ServerHistory.getCurTree();
        
        return getUlnFromTree(uname, root);
    }

     /** Searches for the username {@code uname} in the key directory at epoch {@code ep}.
     *
     *@return the user's entry in the directory or null if the name can't be found.
     */
    public static synchronized UserLeafNode findUserInEpoch(String uname, long ep) {
        SignedTreeRoot str = ServerHistory.getSTR(ep);
        RootNode root = str.getRoot(); 

        return getUlnFromTree(uname, root);
    }

    /** Updates the key directory by handling all current pending registration and 
     * mapping change operations.
     * This function is called at the beginning of the new epoch.
     *
     *@return the tree root for the updated directory, or null in case of an error.
     */
    public static synchronized RootNode updateDirectory() {
  
        // this should never be the case
        if(ServerHistory.getCurSTR() == null){
            ConiksServer.serverLog.error("Trying to update a server without a history.");
            return null;
        }
        
        RootNode curRoot = ServerHistory.getCurTree();
        long curEpoch = ServerHistory.getCurEpoch();

        RootNode newRoot = TreeBuilder.copyExtendTree(curRoot, pendingQueue);

	// it's safe to clear the pending queue.
	pendingQueue.clear();

        return newRoot;
    }

    // traverses down the tree until we reach the requested user leaf node
    // msm: this pretty much repeats the traversal in ServerOps.generateAuthPathProto
    // so we should really find a way to remove this redundancy
    private static synchronized UserLeafNode getUlnFromTree(String username,
                                                     RootNode root) {
        
        // traverse based on lookup index for this name
        byte[] lookupIndex = ServerUtils.unameToIndex(username);
        
        // not worth doing this recursively
        int curOffset = 0;
        TreeNode runner = root;
                
        while (!(runner instanceof UserLeafNode)) {
            
            // direction here is going to be false = left,
            //                               true = right
            boolean direction = ServerUtils.getNthBit(lookupIndex, curOffset);
            
            if (runner == null){
                break;
            }
            
            if (runner instanceof RootNode) {
                
                    RootNode curNodeR = (RootNode) runner;
                    
                    if(!direction){
                        runner = curNodeR.getLeft();
                    }
                    else {
                        runner = curNodeR.getRight();
                    }

                }

                else {
                    InteriorNode curNodeI = (InteriorNode) runner;
               
                    if(!direction){
                        runner = curNodeI.getLeft();
                    }                             
                    else {
                        runner = curNodeI.getRight();
                    }

                    // msm: rather be safe than sorry
                    if (runner == null){
                        break;
                    }
                    
                }
               
                curOffset++;
            }

            // if we have found a uln, make sure it doesn't just have a common prefix
            // with the requested node
            if (runner != null && runner instanceof UserLeafNode) {
                // msm: this is ugly
                if (!username.equals(((UserLeafNode)runner).getUsername())) {
                        return null;
                    }
            }

            // we expect the runner to be the right uln at this point
            return (UserLeafNode) runner;
  
        }

}
