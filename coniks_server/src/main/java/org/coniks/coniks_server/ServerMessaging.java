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

import javax.net.ssl.*;
import java.net.*;
import java.io.*;
import java.util.ArrayList;
import java.security.NoSuchAlgorithmException;

import com.google.protobuf.AbstractMessage;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import org.javatuples.*;

// coniks-java imports
import org.coniks.crypto.Digest;
import org.coniks.util.Logging;
import org.coniks.coniks_common.*;
import org.coniks.coniks_common.C2SProtos.*;
import org.coniks.coniks_common.UtilProtos.*;

/** Implements all of the messaging operations between the server and clients.
 *
 *@author Marcela S. Melara (melara@cs.princeton.edu)
 *@author Aaron Blankstein
 *@author Michael Rochlin
 */
public class ServerMessaging {

    /** Sends a simple server response protobuf based on the
     * result (often an error) of a client request.
     *
     *@param reqResult the result of the request
     *@param socket the client socket to which to send the message
     */
    public static synchronized void sendSimpleResponseProto(int reqResult, Socket socket){
        Logging.log("Sending simple server response... ");

        ServerResp respMsg = buildServerRespMsg(reqResult);
        sendMsgProto(MsgType.SERVER_RESP, respMsg, socket);

    }

    /** Sends the signed tree root protobuf returned for a client's signed tree root request.
     *
     *@param str the signed tree root to send
     *@param socket the client socket to which to send the message
     */
    public static synchronized void sendCommitmentProto(SignedTreeRoot str, Socket socket){
        Logging.log("Sending commitment response... ");

        Commitment comm = buildCommitmentMsg(str);

        sendMsgProto(MsgType.COMMITMENT, comm, socket);
    }

    /** Sends a basic registration response protobuf for a new name-to-key mapping
     * registration.
     *@param regEpoch the epoch at which the mapping will be registered in the directory
     *@param epochInterval the frequency with which the server updates its directory.
     *@param socket the client socket to which to send the message
     */
    public static synchronized void sendRegistrationRespProto(long regEpoch, int epochInterval,
                                                              Socket socket){
        Logging.log("Sending registration response... ");

        RegistrationResp regResp = buildRegistrationRespMsg(regEpoch, epochInterval);
        sendMsgProto(MsgType.REGISTRATION_RESP, regResp, socket);
    }

    /** Sends the authentication path protobuf returned for a client's key lookup.
     *
     *@param uln the key directory entry for which to send the authentication path
     *@param root the key directory root for the authentication path
     *@param socket the client socket to which to send the message
     */
    public static synchronized void sendAuthPathProto(UserLeafNode uln, RootNode root, Socket socket){
        Logging.log("Sending authentication path response... ");

        AuthPath authPath = buildAuthPathMsg(uln, root);
        sendMsgProto(MsgType.AUTH_PATH, authPath, socket);
    }

    /** Sends any protobuf message {@code msg} of type {@code msgType}
     * to the given socket.
     */
    private static synchronized void sendMsgProto (int msgType, AbstractMessage msg,
                                Socket socket) {

        DataOutputStream dout = null;
        try {
            dout = new DataOutputStream(socket.getOutputStream());

            // now send the message
            dout.writeByte(msgType);
            msg.writeDelimitedTo(dout);
            dout.flush();
        }
        catch (IOException e) {
            Logging.error("Sending msg proto "+msg.toString());
            Logging.error("Error: "+e.getMessage());
        }
        finally {
            CommonMessaging.close(dout);
        }

    }

    /* Message building functions */

    // create the simple server response message
    private static synchronized ServerResp buildServerRespMsg(int respType){
        ServerResp.Builder respMsg = ServerResp.newBuilder();
        switch(respType){
        case ServerErr.SUCCESS:
            respMsg.setMessage(ServerResp.Message.SUCCESS);
            break;
        case ServerErr.NAME_EXISTS_ERR:
            respMsg.setMessage(ServerResp.Message.NAME_EXISTS_ERR);
            break;
        case ServerErr.NAME_NOT_FOUND_ERR:
            respMsg.setMessage(ServerResp.Message.NAME_NOT_FOUND_ERR);
            break;
        case ServerErr.MALFORMED_CLIENT_MSG_ERR:
            respMsg.setMessage(ServerResp.Message.MALFORMED_ERR);
            break;
        case ServerErr.SIGNED_CHANGE_VERIF_ERR:
            respMsg.setMessage(ServerResp.Message.VERIFICATION_ERR);
            break;
        default:
            respMsg.setMessage(ServerResp.Message.SERVER_ERR);
            break;
        }
        return respMsg.build();
    }

    // create the commitment response message
    private static synchronized Commitment buildCommitmentMsg(SignedTreeRoot str){

        Commitment.Builder commMsg = Commitment.newBuilder();
        byte[] rootBytes = ServerUtils.getRootNodeBytes(str.getRoot());
        byte[] rootHashBytes = null;

        try {
            rootHashBytes = Digest.digest(rootBytes);
        }
        catch(NoSuchAlgorithmException e) {
            Logging.error("[ServerMessagging] "+e.getMessage());
            return null;
        }

        Hash.Builder rootHash = Hash.newBuilder();
        if(rootHashBytes.length != Digest.HASH_SIZE_BYTES){
            Logging.error("Bad length of root hash: "+rootHashBytes.length);
            return null;
        }
        rootHash.setLen(rootHashBytes.length);
        rootHash.setHash(ByteString.copyFrom(rootHashBytes));
        commMsg.setEpoch(str.getEpoch());
        commMsg.setRootHash(rootHash.build());
        commMsg.setSignature(ByteString.copyFrom(str.getSignature()));
        return commMsg.build();
    }

    // create the registration response message
    private static synchronized RegistrationResp buildRegistrationRespMsg(long initEpoch, int epochInterval){

        RegistrationResp.Builder regRespMsg = RegistrationResp.newBuilder();
        regRespMsg.setInitEpoch(initEpoch);
        regRespMsg.setEpochInterval(epochInterval);
        return regRespMsg.build();
    }

    // create the commitment response message
    private static synchronized AuthPath buildAuthPathMsg(UserLeafNode uln, RootNode root){
        return TransparencyOps.generateAuthPathProto(uln, root);
    }

    /** Receives a protobuf message from the client and checks that
     * the message is correctly formatted for the expected message type.
     * The caller is responsible for handling the exact message type(s).
     *
     *@param socket the client socket from which the message is coming
     *@return The specific protobuf message according to the message type
     * indicated by the client.
     */
    public static synchronized AbstractMessage receiveMsgProto(Socket socket) {

        DataInputStream din = null;
        try {
            din = new DataInputStream(socket.getInputStream());

            // get the message type of the message and read in the stream
            int msgType = din.readUnsignedByte();

            if (msgType == MsgType.REGISTRATION){
                Registration reg = Registration.parseDelimitedFrom(din);

                if(!reg.hasBlob() || !reg.hasChangeKey() || !reg.hasAllowsUnsignedKeychange()
                   || !reg.hasAllowsPublicLookup()) {
                    Logging.log("Malformed registration message");
                }
                else {
                    return reg;
                }
            }
            else if (msgType == MsgType.KEY_LOOKUP) {
                KeyLookup lookup = KeyLookup.parseDelimitedFrom(din);

                if(!lookup.hasName() || !lookup.hasEpoch() ||
                   lookup.getEpoch() <= 0){
                    Logging.log("Malformed key lookup");
                }
                else {
                    return lookup;
                }
            }
            else if (msgType == MsgType.COMMITMENT_REQ) {
                CommitmentReq commReq = CommitmentReq.parseDelimitedFrom(din);

                if (!commReq.hasType() || !commReq.hasEpoch() || commReq.getEpoch() <= 0) {
                    Logging.log("Malformed commitment request message");
                }
                else {
                    return commReq;
                }
            }
            else if (msgType == MsgType.ULNCHANGE_REQ) {
                ULNChangeReq ulnChange = ULNChangeReq.parseDelimitedFrom(din);
                if (!ulnChange.hasName() || !ulnChange.hasNewBlob() || !ulnChange.hasNewChangeKey() ||
                    !ulnChange.hasAllowsUnsignedKeychange() || !ulnChange.hasAllowsPublicLookup()) {
                    Logging.log("Malformed uln change req");
                }
                else {
                    return ulnChange;
                }
            }
            else if (msgType == MsgType.SIGNED_ULNCHANGE_REQ) {
                SignedULNChangeReq sulnReq = SignedULNChangeReq.parseDelimitedFrom(din);
                if (!sulnReq.hasReq() || !sulnReq.hasSig() || !sulnReq.getReq().hasName()) {
                    Logging.log("Malformed signed uln change req");
                }
                else {
                    return sulnReq;
                }
            }
            else {
                Logging.log("Unknown incoming message type");
            }
        }
        catch (InvalidProtocolBufferException e) {
            Logging.error("parsing a protobuf message");
        }
        catch (IOException e) {
            Logging.error("receiving data from client");
        }

        // unexpected message type from the client
        return null;
    }

    /* Functions for handling the lower-level communication with the client */

    /** Listens for incoming requests. Uses an SSL connection if the server is running in
     * full operating mode.
     *
     *@param isFullOp indicates whether the client is operating in full mode
     * or in testing mode
     */
    public static void listenForRequests (boolean isFullOp) {

        ServerSocket s = null;

        try{

            if (isFullOp) {
                SSLServerSocketFactory sslSrvFact =
                (SSLServerSocketFactory)SSLServerSocketFactory.getDefault();
                s =(SSLServerSocket)sslSrvFact.createServerSocket(ServerConfig.getPort());
            }
            else {
                s = new ServerSocket(ServerConfig.getPort());

                System.out.println("Listening for connections on port "+ServerConfig.getPort()+"...");
            }

            Logging.log("Listening for connections on port "+ServerConfig.getPort()+"...");

            // loop to listen for requests
            while(true){
                Socket c = s.accept(); // closing done by thread

                Logging.log("Server accepted new connection.");

                RequestHandler th;

                if (isFullOp) {
                    th = new RequestHandler((SSLSocket)c);
                }
                else {
                    th = new RequestHandler(c);
                }

                th.start();

            }
        }
        catch(IOException e){
            Logging.error("hello: "+e.getMessage());
        }

    }

}
