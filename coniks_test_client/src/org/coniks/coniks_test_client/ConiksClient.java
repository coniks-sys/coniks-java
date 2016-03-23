<<<<<<< HEAD
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

=======
/** Implements the operations that interface
 * a CONIKS client with a CONIKS server.
 * 
 *@author Marcela Melara
 */
>>>>>>> Adding the new files
package org.coniks.coniks_test_client;

import javax.net.ssl.*;
import java.net.*;
import java.io.*;

import com.google.protobuf.*;

import org.coniks.coniks_common.MsgType;
import org.coniks.coniks_common.C2SProtos.Registration;
import org.coniks.coniks_common.C2SProtos.CommitmentReq;
import org.coniks.coniks_common.C2SProtos.KeyLookup;
import org.coniks.coniks_common.C2SProtos.RegistrationResp;
import org.coniks.coniks_common.C2SProtos.AuthPath;
<<<<<<< HEAD
import org.coniks.coniks_common.UtilProtos.Commitment;
import org.coniks.coniks_common.UtilProtos.ServerResp;

/** Implements the operations that interface
 * a CONIKS client with a CONIKS server.
 * 
 *@author Marcela S. Melara (melara@cs.princeton.edu)
 */
public class ConiksClient {

    private static final ClientConfig CONFIG = new ClientConfig();
=======
import org.coniks.coniks_common.C2SProtos.*;

import org.coniks.coniks_common.UtilProtos.Hash;
import org.coniks.coniks_common.UtilProtos.Commitment;
import org.coniks.coniks_common.UtilProtos.ServerResp;
import org.coniks.coniks_common.UtilProtos.*;

import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import javax.crypto.*;
import java.math.BigInteger;
import java.util.Arrays;


public class ConiksClient {

    public static final ClientConfig CONFIG = new ClientConfig();
>>>>>>> Adding the new files

    private static DataOutputStream dout;
    private static DataInputStream din;

    /** Sets the default truststore according to the {@link ClientConfig}.
     * This is needed to set up SSL connections with a CONIKS server.
     */
    public static void setDefaultTruststore() {
        System.setProperty("javax.net.ssl.trustStore", 
                           CONFIG.TRUSTSTORE_PATH);
        System.setProperty("javax.net.ssl.trustStorePassword",
                           CONFIG.TRUSTSTORE_PWD);
<<<<<<< HEAD
=======
        System.setProperty("javax.net.ssl.keyStore", CONFIG.PRIVATE_KEYSTORE_PATH);
        System.setProperty("javax.net.ssl.keyStorePassword", CONFIG.PRIVATE_KEYSTORE_PWD);
>>>>>>> Adding the new files
    }

    /* Functions for sending CONIKS messages to the server */

    /** Sends a Registration protobuf message with the given
        {@code username} and {@code publicKey} to
        to the {@code server}.
    */
    public static void sendRegistrationProto (String username, String publicKey,
                                              String server) {
      
        Registration reg = buildRegistrationMsgProto(username, publicKey);
        sendMsgProto(MsgType.REGISTRATION, reg, server);

    }

    /** Sends a KeyLookup protobuf message with the given
        {@code username} and {@code epoch} to
        to the {@code server}.
    */
    public static void sendKeyLookupProto (String username, long epoch,
                                              String server) {

        KeyLookup lookup = buildKeyLookupMsgProto(username, epoch);
        sendMsgProto(MsgType.KEY_LOOKUP, lookup, server);

    }

    /** Sends a CommitmentReq protobuf message requesting {@code provider}'s 
<<<<<<< HEAD
      commitment for {@code epoch} from {@code server}.
        If the server and provider are the same, {@code commitmentType} 
        is {@code SELF}, otherwise it is {@code WITNESSED}.
=======
        commitment for {@code epoch} from {@code server}.
        If the server and provider are the same, {@code commitmentType} is {@code SELF},
        otherwise it is {@code WITNESSED}.
>>>>>>> Adding the new files
    */
    public static void sendCommitmentReqProto (
                                               CommitmentReq.CommitmentType commitmentType, 
                                               long epoch, String provider,
                                               String server) {
        
<<<<<<< HEAD
        CommitmentReq commReq = buildCommitmentReqMsgProto(
                                                           commitmentType, epoch, provider);
=======
        CommitmentReq commReq = buildCommitmentReqMsgProto(commitmentType, epoch, 
                                                           provider);
>>>>>>> Adding the new files
        sendMsgProto(MsgType.COMMITMENT_REQ, commReq, server);

    }

<<<<<<< HEAD
=======
    /** Sends a ULNChangeReq protobuf message with all the arguments */
    public static void sendULNChangeReqProto(String username, String newBlob, DSAPublicKey newChangeKey,
                                             boolean allowsUnsignedKeychange, boolean allowsPublicLookup,
                                             String server) {
        ULNChangeReq changeReq = buildULNChangeReqMsgProto(username, newBlob, newChangeKey, 
                                                           allowsUnsignedKeychange, allowsPublicLookup);
        // System.out.println("ulnChange: " + Arrays.toString(changeReq.toByteArray()));
        sendMsgProto(MsgType.ULNCHANGE_REQ, changeReq, server);
    }

    /** Sends a SignedULNChangeReq protobuf with all the arguments and signed with {@code prk} */
    public static void sendSignedULNChangeReqProto(String username, String newBlob, DSAPublicKey newChangeKey,
                                         boolean allowsUnsignedKeychange, boolean allowsPublicLookup,
                                         DSAPrivateKey prk,
                                         String server) {
        ULNChangeReq changeReq = buildULNChangeReqMsgProto(username, newBlob, newChangeKey, 
                                                           allowsUnsignedKeychange, allowsPublicLookup);
        // System.out.println("Signed ulnChange: " + Arrays.toString(changeReq.toByteArray()));
        SignedULNChangeReq signed = buildSignedULNChangeReqMsgProto(changeReq, prk);
        sendMsgProto(MsgType.SIGNED_ULNCHANGE_REQ, signed, server);
    }

>>>>>>> Adding the new files
    /* Helper functions for implementing the sending functions */

    /** Sends any protobuf message {@code msg} of type {@code msgType}
     * to the given {@code server}.
     */
    private static void sendMsgProto (int msgType, AbstractMessage msg,
                                String server) {

        try {
            connect(server);

            // now send the message
            dout.writeByte(msgType);
            msg.writeDelimitedTo(dout);
            dout.flush();
        }
        catch (IOException e) {
            System.out.println("Something went wrong while trying to send message: "+
                               msg.toString());
            System.out.println("Error: "+e.getMessage());
        }

    }

    /** Builds the Registration protobuf message with a given
        {@code username} and {@code publicKey}.
    */
<<<<<<< HEAD
    private static Registration buildRegistrationMsgProto(String username, 
                                                          String publicKey) {
        Registration.Builder regBuild = Registration.newBuilder();
        regBuild.setName(username);
        regBuild.setPublickey(publicKey);
=======
    private static Registration buildRegistrationMsgProto(String username, String publicKey) {
        Registration.Builder regBuild = Registration.newBuilder();
        regBuild.setName(username);
        regBuild.setBlob(publicKey);
>>>>>>> Adding the new files

        return regBuild.build();
    }

    /** Builds the KeyLookup protobuf message with a given
        {@code username} and {@code epoch}.
    */
    private static KeyLookup buildKeyLookupMsgProto(String username, long epoch) {
        KeyLookup.Builder keyLookupBuild = KeyLookup.newBuilder();
        keyLookupBuild.setName(username);
        keyLookupBuild.setEpoch(epoch);
     
        return keyLookupBuild.build();
<<<<<<< HEAD
    
=======
>>>>>>> Adding the new files
    }

    /** Builds the CommitmentReq protobuf message with a given
        {@code commType}, {@code epoch}, and {@code server}.
    */
    private static CommitmentReq buildCommitmentReqMsgProto (
                                                            CommitmentReq.CommitmentType commType, 
                                                            long epoch, String server) {
        CommitmentReq.Builder commReqBuild = CommitmentReq.newBuilder();
        commReqBuild.setType(commType);
        commReqBuild.setEpoch(epoch);
        commReqBuild.setProvider(server);
     
        return commReqBuild.build();
<<<<<<< HEAD
    
=======
    }

    /** Builds the ULNChangeReq protobuf message with a given 
        {@code username} {@code blob} {@code changeKey}
        {@code allowsUnsignedKeychange} {@code allowsPublicLookup}
        The blob and changeKey fields may be null if no change is requested
    */
    private static ULNChangeReq buildULNChangeReqMsgProto(String username,
                                                          String blob,
                                                          DSAPublicKey dsa,
                                                          boolean allowsUnsignedKeychange,
                                                          boolean allowsPublicLookup) {
        ULNChangeReq.Builder ulnChangeBuilder = ULNChangeReq.newBuilder();
        ulnChangeBuilder.setName(username);
        if (blob != null) {
            ulnChangeBuilder.setNewBlob(blob);
        }
        if (dsa != null) {
            ulnChangeBuilder.setNewChangeKey(ClientUtils.buildDSAPublicKeyProto(dsa));
        }
        ulnChangeBuilder.setAllowsUnsignedKeychange(allowsUnsignedKeychange);
        ulnChangeBuilder.setAllowsPublicLookup(allowsPublicLookup);
        return ulnChangeBuilder.build();
    }

    /** Builds the SignedULNChangeReq protobuf message with a given 
        {@code changeReq} is a ULNChangeReq that was built previously 
        {@code sig}
        Unlike the other methods, this one actually handles the signing        
    */
    private static SignedULNChangeReq buildSignedULNChangeReqMsgProto(ULNChangeReq changeReq, DSAPrivateKey prk) {

        SignedULNChangeReq.Builder ulnChangeBuilder = SignedULNChangeReq.newBuilder();
        ulnChangeBuilder.setReq(changeReq);

        // TODO (mrochlin)
        // implement signing
        try {
            byte[] sig = SignatureOps.sign(changeReq.toByteArray(), prk);
            System.out.println("Signed ULNChange. Sig: " + Arrays.toString(sig));
            ulnChangeBuilder.addAllSig(ClientUtils.byteArrToIntList(sig));
        }
        catch (InvalidKeyException e) {
            System.out.println("Bad key");
            return null;
        }
        return ulnChangeBuilder.build();
>>>>>>> Adding the new files
    }

    /* Functions for handling messages received from the server */

    /** Receives and parses a RegistrationResp protobuf message
     * from the server.
     *
     *@return The RegistrationResp message upon success. {@code null} otherwise.
     */
    public static RegistrationResp receiveRegistrationRespProto() {
        
        // first receive the generic message from the server
        AbstractMessage serverMsg = receiveMsgProto();

        RegistrationResp regResp = null;

        if (serverMsg == null || 
            !((serverMsg instanceof RegistrationResp) || (serverMsg instanceof ServerResp))) {
            System.out.println("Unexpected server response");
        }
        else if (serverMsg instanceof ServerResp) {
            printServerRespMsgProto((ServerResp)serverMsg);
        }
        else {
            regResp = (RegistrationResp)serverMsg;
        }
        
        return regResp;

    }

     /** Receives and parses an AuthPath protobuf message
     * from the server.
     *
     *@return The AuthPath message upon success. {@code null} otherwise.
     */
    public static AuthPath receiveAuthPathProto() {
        
        // first receive the generic message from the server
        AbstractMessage serverMsg = receiveMsgProto();

        AuthPath authPath = null;

        if (serverMsg == null || 
            !((serverMsg instanceof AuthPath) || (serverMsg instanceof ServerResp))) {
            System.out.println("Unexpected server response");
        }
        else if (serverMsg instanceof ServerResp) {
            printServerRespMsgProto((ServerResp)serverMsg);
        }
        else {
            authPath = (AuthPath)serverMsg;
        }
        
        return authPath;

    }

     /** Receives and parses a Commitment protobuf message
     * from the server 
     *
     *@return The Commitment message upon success. {@code null} otherwise.
     */
    public static Commitment receiveCommitmentProto() {
        
        // first receive the generic message from the server
        AbstractMessage serverMsg = receiveMsgProto();

        Commitment comm = null;

        if (serverMsg == null || 
            !((serverMsg instanceof Commitment) || (serverMsg instanceof ServerResp))) {
            System.out.println("Unexpected server response");
        }
        else if (serverMsg instanceof ServerResp) {
            printServerRespMsgProto((ServerResp)serverMsg);
        }
        else {
            comm = (Commitment)serverMsg;
        }
        
        return comm;

    }

    /* Helper functions for implementing the receiving functions */

    /** Receives a protobuf message from the server the client is currently
     * connected to, and checks that the message is correctly formatted 
     * for the expected message type.
     * The caller is responsible for handling the exact message type(s).
     *
     *@return The specific protobuf message according to the message type
     * indicated by the server.
     */
    private static AbstractMessage receiveMsgProto () {
        
        try {
            // get the message type of the message and read in the stream
            int msgType = din.readUnsignedByte();
             
<<<<<<< HEAD
            // TODO: this should be a temporary binding
=======
            // TODO: this should be a signed promise/temporary binding
>>>>>>> Adding the new files
            if (msgType == MsgType.REGISTRATION_RESP){
                RegistrationResp regResp = RegistrationResp.parseDelimitedFrom(din);
                
                if(!regResp.hasInitEpoch() || !regResp.hasEpochInterval()){
                    System.out.println("Malformed registration response");
                }
                else {
                    return regResp;
                }
            }
            else if (msgType == MsgType.AUTH_PATH) {
                AuthPath authPath = AuthPath.parseDelimitedFrom(din);
                
                if (!authPath.hasLeaf() || !authPath.hasRoot()) {
                    System.out.println("Malformed auth path");
                }
                else {
                    return authPath;
                }
            }
            else if (msgType == MsgType.COMMITMENT) {
                Commitment comm = Commitment.parseDelimitedFrom(din);
                
                if (!comm.hasEpoch() || !comm.hasRootHash()) {
                    System.out.println("Malformed commitment");
                }
                else {
                    return comm;
                }
            }
            
            // Some error occurred so the server responded with a simple response
            else if (msgType == MsgType.SERVER_RESP) {
                ServerResp resp = ServerResp.parseDelimitedFrom(din);
                
                if (!resp.hasMessage()) {
                    System.out.println("Malformed simple server response");
                }
                else {
                    return resp;
                }
            }
        }
        catch (InvalidProtocolBufferException e) {
            System.out.println("An error occurred while parsing a protobuf message");
        }
        catch (IOException e) {
            System.out.println("An error occurred while receiving data from the server");
        }
        
        close();

        // unexpected message type from the server
        return null;

    }

    /** Retrieves the simple server response message from {@code serverResp}
     * and prints out an appropriate message to stdout.
     */
    private static void printServerRespMsgProto(ServerResp serverResp) {

        ServerResp.Message respType = serverResp.getMessage();

        switch(respType) {
        case SUCCESS:
            System.out.println("Server successful.");
            break;
        case NAME_EXISTS_ERR:
            System.out.println("The name you tried to register already exists.");
            break;
        case NAME_NOT_FOUND_ERR:
            System.out.println("The name you tried to look up could not be found.");
            break;
        case MALFORMED_ERR:
            System.out.println("The message received by the server was malformed.");
            break;
<<<<<<< HEAD
=======
        case VERIFICATION_ERR:
            System.out.println("There was a VERIFICATION_ERR");
            break;
>>>>>>> Adding the new files
        default:
            System.out.println("Some server error occurred.");
            break;                
        }

    }

    /* Functions for handling the lower-level communication with the server */

    /** Establishes an SSL connection to {@code server}.
     *
<<<<<<< HEAD
     *@throws an {@link java.io.IOException} if any of the socket operations fail.
=======
     *@throws an {@code IOException} if any of the socket operations fail.
>>>>>>> Adding the new files
     */
    private static void connect (String server) 
        throws IOException {

        SSLSocketFactory sslFact =
            (SSLSocketFactory)SSLSocketFactory.getDefault();

        SSLSocket sslSock = (SSLSocket)sslFact.createSocket(server, CONFIG.PORT);
        dout = new DataOutputStream(sslSock.getOutputStream());
        din = new DataInputStream(sslSock.getInputStream());
        
    }

    /** Closes the currently open connection to a server
     */
    private static void close() {
        try {
            din.close();
            dout.close();
        }
        catch (IOException e) {
            System.out.println("An error occurred while closing the connection");
        }
    }

<<<<<<< HEAD
=======

>>>>>>> Adding the new files
}
