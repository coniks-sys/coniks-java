package org.coniks.coniks_server;

import javax.net.ssl.*;
import java.net.*;
import java.io.*;

import com.google.protobuf.*;

import org.coniks.coniks_common.MsgType;
import org.coniks.coniks_common.ServerErr;
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

public class ServerMessaging {

    // send back a simple server response based on the result of the request
    public static synchronized void sendSimpleResponseProto(int reqResult
                                                      Socket socket){
        msgLog.log("Sending simple server response... ");
        
        ServerResp respMsg = buildServerRespMsg(reqResult);
        sendMsgProto(MsgType.SERVER_RESP, respMsg, socket);     

    }
    
    // send back the commitment returned for the commitment request
    public static synchronized void sendCommitmentProto(Pair<RootNode, 
                                                        byte[]> commPair, Socket socket){
        msgLog.log("Sending commitment response... ");
     
        Commitment comm = buildCommitmentMsg(commPair.getValue0(), 
                                             commPair.getValue1());
        byte[] rootBytes = ServerUtils.convertRootNode(commPair.getValue0());
        msgLog.log("Root hash "+
                   ServerUtils.bytesToHex(ServerUtils.hash(rootBytes))
                   +"\n Epoch: "+commPair.getValue0().getEpoch()
                   +"\n Prev: "+ServerUtils.bytesToHex(commPair.getValue0().getPrev()));
      
        sendMsgProto(MsgType.COMMITMENT, comm, socket);
    }
    
    // send back the initial epoch and epoch interval for the newly registered user, who will cache this info
    public static synchronized void sendRegistrationRespProto(long initEpoch, int epochInterval,
                                                              Socket socket){
        msgLog.log("Sending registration response... ");
          
        RegistrationResp regResp = buildRegistrationRespMsg(initEpoch, epochInterval);
        sendMsgProto(MsgType.REGISTRATION_RESP, regResp, socket);
    }
    
    // send back the authentication path based on the key lookup
    public static synchronized void sendAuthPathProto(UserLeafNode uln, RootNode root, Socket socket){
        msgLog.log("Sending authentication path response... ");
  
        AuthPath authPath = buildAuthPathMsg(uln, root);
        sendMsgProto(MsgType.AUTH_PATH, authPath, socket);
    }
    
    /** Sends any protobuf message {@code msg} of type {@code msgType}
     * to the given socket.
     */
    private static synchronized void sendMsgProto (int msgType, AbstractMessage msg,
                                Socket socket) {

        try {
            DataOutputStream dout = new DataOutputStream(socket.getOutputStream());

            // now send the message
            dout.writeByte(msgType);
            msg.writeDelimitedTo(dout);
            dout.flush();
        }
        catch (IOException e) {
            msgLog.error("Sending msg proto "+msg.toString());
            msgLog.error("Error: "+e.getMessage());
        }
        finally {
            if (dout != null) {
                dout.close();
            }
        }

    }    

    /* Message building functions */
    
    // create the simple server response message
    private ServerResp buildServerRespMsg(int respType){
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
    private Commitment buildCommitmentMsg(RootNode root, byte[] commSig){            
        
        Commitment.Builder commMsg = Commitment.newBuilder();
        byte[] rootBytes = ServerUtils.convertRootNode(root);
        byte[] rootHashBytes = ServerUtils.hash(rootBytes);
        
        Hash.Builder rootHash = Hash.newBuilder();
        ArrayList<Integer> rootHashList = ServerUtils.byteArrToIntList(rootHashBytes);
        
        if(rootHashList.size() != ServerUtils.HASH_SIZE_BYTES){
            msgLog.error("Bad length of root hash: "+rootHashList.size());
            return null;
        }
        rootHash.setLen(rootHashList.size());
        rootHash.addAllHash(rootHashList);
        commMsg.setEpoch(root.getEpoch());
        ArrayList<Integer> sigList = ServerUtils.byteArrToIntList(commSig);
        commMsg.setRootHash(rootHash.build());
        commMsg.addAllSignature(sigList);
        return commMsg.build();
    }
    
    // create the registration response message
    private RegistrationResp buildRegistrationRespMsg(long initEpoch, int epochInterval){            
        
        RegistrationResp.Builder regRespMsg = RegistrationResp.newBuilder();
        regRespMsg.setInitEpoch(initEpoch);
        regRespMsg.setEpochInterval(epochInterval);
        return regRespMsg.build();
    }
    
    // create the commitment response message
    private AuthPath buildAuthPathMsg(UserLeafNode uln, RootNode root){            
        return ServerOps.generateAuthPathProto(uln, root);
    }

    /** Receives a protobuf message from the client and checks that
     * the message is correctly formatted for the expected message type.
     * The caller is responsible for handling the exact message type(s).
     *
     *@return The specific protobuf message according to the message type
     * indicated by the client.
     */
    public static synchronized AbstractMessage receiveMsgProto(Socket socket) {
        
        try {
            DataInputStream din = new DataInputStream(socket.getInputStream());
            
            // get the message type of the message and read in the stream
            msgType = din.readUnsignedByte();
            
            if (msgType == MsgType.REGISTRATION){
                Registration reg = Registration.parseDelimitedFrom(din);
                
                if(!reg.hasBlob()){
                    msgLog.log("Malformed registration message");
                }
                else {
                    return reg;
                }
            }
            else if (msgType == MsgType.KEY_LOOKUP) {
                KeyLookup lookup = KeyLookup.parseDelimitedFrom(din);
                
                if(!lookup.hasName() || !lookup.hasEpoch() || 
                   lookup.getEpoch() <= 0){
                    msgLog.log("Malformed key lookup");
                }
                else {
                    return lookup;
                }
            }
            else if (msgType == MsgType.COMMITMENT_REQ) {
                CommitmentReq commReq = CommitmentReq.parseDelimitedFrom(din);
                
                if (!commReq.hasType() || !commReq.hasEpoch() || commReq.getEpoch() <= 0) {
                    msgLog.log("Malformed commitment request message");
                }
                else {
                    return commReq;
                }
            }
            else if (msgType == MsgType.ULNCHANGE_REQ) {
                ULNChangeReq ulnChange = ULNChangeReq.parseDelimitedFrom(din);
                if (!ulnChange.hasName()) {
                    msgLog.log("Malformed uln change req");
                }
                else {
                    return ulnChange;
                }
            }
            else if (msgType == MsgType.SIGNED_ULNCHANGE_REQ) {
                SignedULNChangeReq sulnReq = SignedULNChangeReq.parseDelimitedFrom(din);
                if (!sulnReq.hasReq() || sulnReq.getSigCount() < 1 || !sulnReq.getReq().hasName()) {
                    msgLog.log("Malformed signed uln change req");
                }
                else {
                    return sulnReq;
                }
            }
            else {
                // result = ServerUtils.RespType.SERVER_ERR;
                msgLog.log("Unknown incoming message type");
            }
        }
        catch (InvalidProtocolBufferException e) {
            if (isFullOp) {
                msgLog.error("parsing a protobuf message");
            }
            else {
                printStatusMsg(true, "parsing a protobuf message");
            }
        }
        catch (IOException e) {
            if (isFullOp) {
                msgLog.error("receiving data from client");
            }
            else {
                printStatusMsg(true, "receiving data from client");
            }
        }
        finally {
            if (din != null) {
                din.close();
            }
        }
        
        // unexpected message type from the client
        return null;
    }
    

    /* Functions for handling the lower-level communication with the client */

    /** Listens over an SSL connection if in full operating mode.
     *
     *@param server the CONIKS server to which send the message
     *@param isFullOp indicates whether the client is operating in full mode 
     * or in testing mode
     *@throws an {@code IOException} if any of the socket operations fail.
     */
    public static void listenAndAccept (String server, boolean isFullOp) 
        throws IOException {

        ServerSocket s;
        
        try{

            if (isFullOp) {
                SSLServerSocketFactory sslSrvFact = 
                (SSLServerSocketFactory)SSLServerSocketFactory.getDefault();
                s =(SSLServerSocket)sslSrvFact.createServerSocket(CONFIG.PORT);
            }
            else {
                s = new ServerSocket(CONFIG.PORT);

                System.out.println("Listening for connections on port "+CONFIG.PORT+"...");
            }            

            serverLog.log("Listening for connections on port "+CONFIG.PORT+"...");
            
            // loop to listen for requests
            while(true){
                Socket c = s.accept(); // closing done by thread
                
                serverLog.log("Server accepted new connection.");
                
                RequestHandler th = new RequestHandler(c);
                th.start();
                
            }
        }
        catch(Exception e){
            serverLog.error("Exception: " + e.getMessage());
	    e.printStackTrace();
            System.exit(-1);
        }
        
    }
    
}
