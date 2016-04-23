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

package org.coniks.coniks_test_client;

import javax.net.ssl.*;
import java.net.*;
import java.io.*;
import java.util.ArrayList;

import com.google.protobuf.*;
import org.javatuples.*;

import org.coniks.coniks_common.ServerErr;
import org.coniks.coniks_common.C2SProtos.RegistrationResp;
import org.coniks.coniks_common.C2SProtos.AuthPath;
import org.coniks.coniks_common.UtilProtos.Commitment;
import org.coniks.coniks_common.UtilProtos.ServerResp;

/** Implements all consistency check operations done by a CONIKS client
 * on data received from a CONIKS server.
 * These include data binding proof verification,
 * and non-equivocation checks.
 * 
 *@author Marcela S. Melara (melara@cs.princeton.edu)
 */
public class ConsistencyChecks {

    /** Recomputes the root node from an AuthPath protobuf message
     * {@code authPath}.
     *
     *@return The recomputed root node as a {@code byte[]} or {@code null} 
     * upon failure.
     */
    private static byte[] recomputeAuthPathRootProto(AuthPath authPath){
        
        AuthPath.UserLeafNode apUln = authPath.getLeaf();        
       
        ArrayList<Integer> lookupIndexList = new ArrayList<Integer>(
                                                                    apUln.getLookupIndexList());

        byte[] lookupIndex = ClientUtils.intListToByteArr(lookupIndexList);
        int numInteriors = apUln.getIntlevels();

        byte[] ulnHash = ClientUtils.hash(ClientUtils.ulnProtoToBytes(apUln));
        
        ArrayList<AuthPath.InteriorNode> inList = 
            new ArrayList<AuthPath.InteriorNode>(authPath.getInteriorList());

        if(inList.size() != numInteriors){
            ClientLogger.error("Bad length of auth path");
            return null;
        }

        byte[] interiorsHash = ClientUtils.computeInteriorNodeProtoHashes(ulnHash, inList);

        if (interiorsHash == null) {
            return null;
        }

        AuthPath.RootNode root = authPath.getRoot();

        if(!root.hasPrunedchild() || !root.hasSubtree()){
            ClientLogger.error("Root malformed");
            return null;
        }
        
        return ClientUtils.rootProtoToBytes(interiorsHash, root);

    }

    /** Verifies that a given data binding is consistent with the server's STR
     * using the proof {@code authPath} and the STR {@code comm}.
     *
     *@return A {@link utils.ConsistencyErr} error code. {@code NO_ERR} indicates
     * that the verification passed.
     */
    public static int verifyDataBindingProto (AuthPath authPath, 
                                                             Commitment comm){

        // this really shouldn't be null at this point, but we'll check jic
        if (authPath == null /*|| comm == null*/) {
            return ServerErr.MALFORMED_SERVER_MSG_ERR;
        }
        
        // first recompute the root node from the authentication path
        byte[] recomputedRoot = recomputeAuthPathRootProto(authPath);
       
        if (recomputedRoot == null) {
            return ServerErr.MALFORMED_SERVER_MSG_ERR;
        }

        // verify the signature on the commitment
        // TODO: implement this

        // compute the hash of the recomputed root
        byte[] recomputedRootHash = ClientUtils.hash(recomputedRoot);

        // get the received root hash from the commitment and compare
        // the two byte buffers
        // TODO: implement this

        return ConsistencyErr.CHECK_PASSED;

    }

}
