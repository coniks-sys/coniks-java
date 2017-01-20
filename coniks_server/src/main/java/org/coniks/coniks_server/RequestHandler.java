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

import java.net.*;
import java.io.*;
import java.util.Arrays;
import java.util.ArrayList;

import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.DSAParams;

import com.google.protobuf.AbstractMessage;
import com.google.protobuf.ByteString;

// coniks-java imports
import org.coniks.crypto.*;
import org.coniks.util.Convert;
import org.coniks.util.Logging;

import org.coniks.coniks_common.MsgType;
import org.coniks.coniks_common.C2SProtos.Registration;
import org.coniks.coniks_common.C2SProtos.CommitmentReq;
import org.coniks.coniks_common.C2SProtos.KeyLookup;
import org.coniks.coniks_common.C2SProtos.RegistrationResp;
import org.coniks.coniks_common.C2SProtos.AuthPath;
import org.coniks.coniks_common.C2SProtos.*;

import org.coniks.coniks_common.UtilProtos.Hash;
import org.coniks.coniks_common.UtilProtos.Commitment;
import org.coniks.coniks_common.UtilProtos.ServerResp;
import org.coniks.coniks_common.UtilProtos.*;
import org.coniks.coniks_common.ServerErr;
import org.coniks.coniks_common.CommonMessaging;

import org.javatuples.Pair;

/** Implements the request handler for the CONIKS server.
 *
 * @author Marcela Melara (melara@cs.princeton.edu)
 * @author Michael Rochlin
 *
 */
public class RequestHandler extends Thread{

    private Socket clientSocket;
    private long regEpoch;

    /** Constructor of a RequestHandler
     *
     * @param c the client socket
     */
    public RequestHandler(Socket c){
        this.clientSocket = c;
    }

    /** Receives the incoming request as a protobuf message and passes it to the
     * appropriate message handler according to the message type.
     */
    public void run(){

        try{

            AbstractMessage clientMsg = ServerMessaging.receiveMsgProto(clientSocket);

            if (clientMsg == null) {
                ServerMessaging.sendSimpleResponseProto(
                                                        ServerErr.MALFORMED_CLIENT_MSG_ERR,
                                                        clientSocket);
            }
            else if (clientMsg instanceof Registration) {
                handleRegistrationProto((Registration) clientMsg);
            }
            else if (clientMsg instanceof CommitmentReq) {
                handleCommitmentReqProto((CommitmentReq) clientMsg);
            }
            else if (clientMsg instanceof KeyLookup) {
                handleKeyLookupProto((KeyLookup) clientMsg);
            }
            else if (clientMsg instanceof ULNChangeReq) {
                // TODO
                handleULNChangeProto((ULNChangeReq) clientMsg);
            }
            else if (clientMsg instanceof SignedULNChangeReq) {
                // TODO
                handleSignedULNChangeProto((SignedULNChangeReq) clientMsg);
            }
            else {
                ServerMessaging.sendSimpleResponseProto(
                                                        ServerErr.MALFORMED_CLIENT_MSG_ERR,
                                                        clientSocket);
            }

        }
        catch(IOException e){
            Logging.error("Error connecting to client: "+e.getMessage());
            e.printStackTrace();
        }

    } //ends run()

    /* Message handlers */
    private void handleRegistrationProto(Registration reg)
        throws IOException{
        Logging.log("Handling registration message... ");

        // I suppose we want to check the input again just in case
        if(!reg.hasBlob() || !reg.hasChangeKey() || !reg.hasAllowsUnsignedKeychange()
           || !reg.hasAllowsPublicLookup()){
            Logging.log("req handler: Malformed registration message");
            ServerMessaging.sendSimpleResponseProto(ServerErr.MALFORMED_CLIENT_MSG_ERR,
                                               clientSocket);
            return;
        }

        // want to check first whether the name already
        // exists in the database before we register, if it does, reply with error
        String name =reg.getName();
        UserLeafNode uln = DirectoryOps.findUser(name);

        if (uln != null) {
            Logging.error("Found: "+
                         Convert.bytesToHex(ServerUtils.unameToIndex(uln.getUsername()))+
                         "\n"+uln.getUsername()+" found when trying to insert "+name);
            ServerMessaging.sendSimpleResponseProto(ServerErr.NAME_EXISTS_ERR, clientSocket);
            return;
        }

        this.regEpoch = ServerHistory.nextEpoch();

        // If using a DB, insert the new user

        // convert the DSA Key proto back to a Java DSA public key
        DSAPublicKeyProto ckProto = reg.getChangeKey();

        DSAPublicKey ck = KeyOps.makeDSAPublicKeyFromProto(ckProto);

        // we register the user in the pendingQueue
        DirectoryOps.register(name, reg.getBlob(), ck, reg.getAllowsUnsignedKeychange(),
                              reg.getAllowsPublicLookup(), this.regEpoch);

        ServerMessaging.sendRegistrationRespProto(regEpoch,
                                                  ServerConfig.getEpochInterval(), clientSocket);

    }

    // retrieves the root node and commitment signature given a specific commitment request
    private void handleCommitmentReqProto(CommitmentReq commReq)
        throws IOException{

        long epoch = commReq.getEpoch();
        long curEpoch = ServerHistory.getCurEpoch();
        // if we get a request for an epoch we haven't reached yet, return the current
        if(epoch > curEpoch){
            epoch = curEpoch;
        }

        Logging.log("Getting commitment for epoch "+epoch+"...");

        CommitmentReq.CommitmentType commType = commReq.getType();

        // TODO: handle requests for observed commitments
        if(commType == CommitmentReq.CommitmentType.SELF){
            SignedTreeRoot str = ServerHistory.getSTR(epoch);

            ServerMessaging.sendCommitmentProto(str, clientSocket);
        }

    }

    // retrieves the user leaf node given a specific key lookup
    private void handleKeyLookupProto(KeyLookup lookup)
        throws IOException{

        long epoch = lookup.getEpoch();
        long curEpoch = ServerHistory.getCurEpoch();
        if(epoch > curEpoch){
            epoch = curEpoch;
        }

        String username = lookup.getName();

        Logging.log("Getting key for "+username+"... ");

        Logging.log("SHA256 of name: " + Convert.bytesToHex(ServerUtils.unameToIndex(username)));

        RootNode root = ServerHistory.getSTR(epoch).getRoot();
        UserLeafNode uln = DirectoryOps.findUserInEpoch(username, epoch);

        if(uln == null){
            Logging.error(username + " not found...");
            ServerMessaging.sendSimpleResponseProto(ServerErr.NAME_NOT_FOUND_ERR, clientSocket);
            return;
        }

        ServerMessaging.sendAuthPathProto(uln, root, clientSocket);
    }

    /* Helper functions for ULN changes (without sig) */

    // retrieves the user leaf node given a specific key lookup
    private synchronized void handleULNChangeProto(ULNChangeReq changeReq)
        throws IOException{
        handleULNChangeProto(changeReq, null);
    }

    // Handles a proto that might have a sig
    private synchronized void handleULNChangeProto(ULNChangeReq changeReq, byte[] sig)
        throws IOException{

        if (!changeReq.hasName() || !changeReq.hasNewBlob() || !changeReq.hasNewChangeKey() ||
            !changeReq.hasAllowsUnsignedKeychange() || !changeReq.hasAllowsPublicLookup()) {
            Logging.log("Malformed uln change req");
        }

        String username = changeReq.getName();

        UserLeafNode uln = DirectoryOps.findUser(username);

        if(uln == null){
            Logging.error(username + " not found...");
            ServerMessaging.sendSimpleResponseProto(ServerErr.NAME_NOT_FOUND_ERR, clientSocket);
            return;
        }

        // make sure the request has a signature if the user requires one
        // wew assume the signature has been verified at this point
        if (!uln.allowsUnsignedKeychange() && sig == null) {
            Logging.error("Required signature for "+username+" not found");
            ServerMessaging.sendSimpleResponseProto(ServerErr.MALFORMED_CLIENT_MSG_ERR, clientSocket);
            return;
        }

        boolean allowsUnsignedKC = changeReq.hasAllowsUnsignedKeychange() ? changeReq.getAllowsUnsignedKeychange() : uln.allowsUnsignedKeychange();
        boolean allowsPublicLookup = changeReq.hasAllowsPublicLookup() ? changeReq.getAllowsPublicLookup() : uln.allowsPublicLookups();
        String newBlob = changeReq.hasNewBlob() ? changeReq.getNewBlob() : uln.getPublicKey();
        DSAPublicKey newChangeKey = changeReq.hasNewChangeKey() ? KeyOps.makeDSAPublicKeyFromProto(changeReq.getNewChangeKey()) : uln.getChangeKey();

        DirectoryOps.mappingChange(username, newBlob, newChangeKey, allowsUnsignedKC, allowsPublicLookup, newBlob.getBytes(), sig);
        Logging.log("ulnChange: " + Arrays.toString(changeReq.toByteArray()));

        // If using a DB, insert the new user

        // Send a registration response so that the client knows when to check
        // that the changes were actually comitted
        this.regEpoch = ServerHistory.nextEpoch();

        ServerMessaging.sendRegistrationRespProto(regEpoch, ServerConfig.getEpochInterval(), clientSocket);
    }

    /* Helper functions for ULN changes (with sig) */
    private synchronized void handleSignedULNChangeProto(SignedULNChangeReq signedReq)
        throws IOException{

        ULNChangeReq changeReq = signedReq.getReq();

        if (!changeReq.hasName() || !changeReq.hasNewBlob() || !changeReq.hasNewChangeKey() ||
            !changeReq.hasAllowsUnsignedKeychange() || !changeReq.hasAllowsPublicLookup()) {
            Logging.log("Malformed uln change req");
        }

        String username = changeReq.getName();

        // get the uln
        UserLeafNode uln = DirectoryOps.findUser(username);

        if(uln == null){
            Logging.error(username + " not found...");
            ServerMessaging.sendSimpleResponseProto(ServerErr.NAME_NOT_FOUND_ERR, clientSocket);
            return;
        }

        // verify signature
        DSAPublicKey publicChangeKey = uln.getChangeKey();

        byte[] reqMsg = changeReq.toByteArray();
        byte[] sig = signedReq.getSig().toByteArray();

        boolean res = false;

        try {
            res = Signing.dsaVerify(publicChangeKey, reqMsg, sig);
        }
        // let's catch the panic here and log it
        catch (Exception e) {
            Logging.error("[RequestHandler] "+e.getMessage());
        }

        if (!res) {
            Logging.log("Failed to verify message");
            Logging.log("Failed sig said\n" + Arrays.toString(sig));
            ServerMessaging.sendSimpleResponseProto(ServerErr.SIGNED_CHANGE_VERIF_ERR, clientSocket);
            return;
        }

        // now pass to the unsigned version of the handler
        handleULNChangeProto(changeReq, sig);
    }

}
