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

import com.google.protobuf.ByteString;

// coniks-java imports
import org.coniks.crypto.Signing;
import org.coniks.crypto.Util;
import org.coniks.coniks_common.C2SProtos.AuthPath;
import org.coniks.coniks_common.C2SProtos.*;
import org.coniks.coniks_common.UtilProtos.Hash;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.TreeMap;
import java.util.PriorityQueue;
import java.security.*;
import java.security.interfaces.*;
import java.nio.ByteBuffer;

import org.javatuples.*;

/** Implements all transparency-related operations done by a
 * CONIKS server.
 * These allow a CONIKS client to perform the consistency checks.
 *
 *@author Marcela S. Melara (melara@cs.princeton.edu)
 *@author Aaron Blankstein
 *@author Michael Rochlin
 */
public class TransparencyOps{

    /** Generates the STR from the root node {@code root}, the epoch
     * {@code ep}, the previous epoch {@code prevEp}, and the previous
     * STR's hash {@code prevStrHash}.
     *
     *@return The signed tree root, or {@code null} in case of an error.
     */
    public static SignedTreeRoot generateSTR(RootNode root, long ep,
                                             long prevEp, byte[] prevStrHash) {

        byte[] strBytesPreSig = ServerUtils.getSTRBytesForSig(root, ep, prevEp,
                                                              prevStrHash);

        RSAPrivateKey key = KeyOps.loadSigningKey();

        byte[] sig = null;
        try {
            sig = Signing.rsaSign(key, strBytesPreSig);
        }
        catch (Exception e) {
            ServerLogger.error("[RequestHandler] "+e.getMessage());
            return null;
        }

        return new SignedTreeRoot(root, ep, prevEp, prevStrHash, sig, null);
    }

    /** Generates the STR from the root node {@code root} for the epoch
     * {@code ep}.
     * Hashes the current STR, and computes the signature for the next STR.
     *
     *@return The signed tree root, or {@code null} in case of an error.
     */
    public static synchronized SignedTreeRoot generateNextSTR(RootNode root, long ep){

        long prevEpoch = ServerHistory.getCurEpoch();

        // generate the hash of the current STR to include is in the next
        // STR as the previous STR hash
        byte[] prevStrHash = null;

        try {
            prevStrHash = Util.digest(ServerUtils.getSTRBytes(ServerHistory.getCurSTR()));
        }
        catch(NoSuchAlgorithmException e) {
            ServerLogger.error("[TransparencyOps] "+e.getMessage());
            return null;
        }

        byte[] strBytesPreSig = ServerUtils.getSTRBytesForSig(root, ep, prevEpoch,
                                                              prevStrHash);

        RSAPrivateKey key = KeyOps.loadSigningKey();

        byte[] sig = null;
        try {
            sig = Signing.rsaSign(key, strBytesPreSig);
        }
        catch (Exception e) {
            ServerLogger.error("[TransparencyOps] "+e.getMessage());
            return null;
        }

        return new SignedTreeRoot(root, ep, prevEpoch, prevStrHash, sig, ServerHistory.getCurSTR());
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
        AuthPath.UserLeafNode.Builder ulnBuilder = AuthPath.UserLeafNode.newBuilder();
        ulnBuilder.setName(uln.getUsername());
        ulnBuilder.setPublickey(uln.getPublicKey());
        ulnBuilder.setEpochAdded(uln.getEpochAdded());
        ulnBuilder.setAllowsUnsignedKeychange(uln.allowsUnsignedKeychange());
        ulnBuilder.setAllowsPublicLookup(uln.allowsPublicLookups());
        ulnBuilder.setLookupIndex(ByteString.copyFrom(uln.getIndex()));
        ulnBuilder.setEpochChanged(uln.getEpochChanged());
        if (uln.getSignature() != null)
            ulnBuilder.setSignature(ByteString.copyFrom(uln.getSignature()));


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
            ulnBuilder.setLastMsg(ByteString.copyFrom(uln.getLastMsg()));

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

            byte[] prunedChildHash = new byte[Util.HASH_SIZE_BYTES];

            if (runner == null){
                ServerLogger.error("Null runner" + curOffset);
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
                if(prunedChildHash.length != Util.HASH_SIZE_BYTES){
                    ServerLogger.error("Bad length of pruned child hash: "+prunedChildHash.length);
                    return null;
                }
                subtree.setLen(prunedChildHash.length);
                subtree.setHash(ByteString.copyFrom(prunedChildHash));
                rootBuilder.setSubtree(subtree.build());

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
                  if(prunedChildHash.length != Util.HASH_SIZE_BYTES){
                    ServerLogger.error("Bad length of pruned child hash: "+prunedChildHash.length);
                    return null;
                }
                subtree.setLen(prunedChildHash.length);
                subtree.setHash(ByteString.copyFrom(prunedChildHash));
                inBuilder.setSubtree(subtree.build());
                interiorList.add(0, inBuilder.build());

                if (runner == null){
                    ServerLogger.error("such sadness...");
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

}
