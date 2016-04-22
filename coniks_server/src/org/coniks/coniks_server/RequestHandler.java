package org.coniks.coniks_server;

import javax.net.ssl.*;
import java.net.*;

import com.google.protobuf.*;

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

/** Implements the message handling for the CONIKS server
 *
 * @author Marcela Melara (melara@cs.princeton.edu)
 *
 */
private static class RequestHandler extends Thread{
        
    private Socket clientSocket;
    private long regEpoch;
    private int msgType;
    
    /** Constructor of a RequestHandler
     *
     * @param s the client socket
     */
    public RequestHandler(Socket c){
        
        if (isFullOp) {
            this.clientSocket = (SSLSocket)c;
        }
        else {
            this.clientSocket = c;
        }
    }
    
    /** Runs the ServerThread: calls the handle connection method
     * Will have a switch statement for each message type received
     */
    public void run(){
        
        try{	
            
            AbstractMessage clientMsg = ServerMessaging.receiveMsgProto(clientSocket);
            
            if (clientMsg == null) {
                ServerMessaging.sendSimpleResponseProto(ServerUtils.RespType.MALFORMED_ERR,
                                                        clientSocket);
            }
            else if (msgType == MsgType.REGISTRATION) {
                handleRegistrationProto((Registration) clientMsg);
            }
            else if (msgType == MsgType.COMMITMENT_REQ) {
                handleCommitmentReqProto((CommitmentReq) clientMsg);
            }
            else if (msgType == MsgType.KEY_LOOKUP) {
                handleKeyLookupProto((KeyLookup) clientMsg);
            }
            else if (msgType == MsgType.ULNCHANGE_REQ) {
                // TODO
                handleULNChangeProto((ULNChangeReq) clientMsg);
            }
            else if (msgType == MsgType.SIGNED_ULNCHANGE_REQ) {
                // TODO
                handleSignedULNChangeProto((SignedULNChangeReq) clientMsg);
            }
            else {
                ServerMessaging.sendSimpleResponseProto(ServerUtils.RespType.MALFORMED_ERR,
                                                        clientSocket);
            }
            
        }
        catch(IOException e){
            if (isFullOp) {
                msgLog.error("Error connecting to client: "+e.getMessage());
            }
            else {
                printStatusMsg(true, "Error connecting to client: "+e.getMessage());
            }
            e.printStackTrace();
        }
        finally {
            if (clientSocket != null) {
                clientSocket.close();
            }
        }
        
    } //ends run()
    
    /* Message handlers */
    private synchronized void handleRegistrationProto(Registration reg) 
        throws IOException{
        msgLog.log("Handling registration message... ");
        
        if(!reg.hasBlob()){
            msgLog.log("Malformed registration message");
            ServerMessaging.sendSimpleResponse(ServerErr.MALFORMED_CLIENT_MSE_ERR, 
                                               clientSocket);
            return;
        }
        
        // want to check first whether the name already 
        // exists in the database before we register, if it does, reply with error
        String name =reg.getName();
        UserLeafNode uln = DirectoryOps.find(name);
        
        if (uln != null) {
            msgLog.error("Found: "+
                         ServerUtils.bytesToHex(ServerUtils.unameToIndex(uln.getUsername()))+
                         "\n"+uln.getUsername()+" found when trying to insert "+name);
            ServerMessaging.sendSimpleResponse(ServerErr.NAME_EXISTS_ERR, clientSocket);
            return;
        }
        
        long curEpoch = ServerHistory.curSTR.getEpoch();
        this.regEpoch = curEpoch+ConiksServer.CONFIG.EPOCH_INTERVAL;
        
        // If using a DB, insert the new user
        
        // we register the user in the pendingQueue
        DirectoryOps.register(name, reg.getBlob());
        
        ServerMessaging.sendRegistrationRespResponse(regEpoch, 
                                                     ConiksServer.CONFIG.EPOCH_INTERVAL);
        
    }
    
    // retrieves the root node and commitment signature given a specific commitment request
    private synchronized void handleCommitmentReqProto(CommitmentReq commReq) 
        throws IOException{
        
        long epoch = commReq.getEpoch();
        // if we get a request for an epoch we haven't reached yet, return the current
        if(epoch > curEpoch){
            epoch = curEpoch;
        }
        
        msgLog.log("Getting commitment for epoch "+epoch+"...");
        
        CommitmentReq.CommitmentType commType = commReq.getType();
        
        // TODO: handle requests for observed commitments
        if(commType == CommitmentReq.CommitmentType.SELF){
            ServerUtils.Record record = getRecord(epoch);
            
            // TODO: what to do if record not found?
            
            RootNode root = record.getRoot();
            byte[] str = record.getSTR();
            
            ServerMessaging.sendCommitmentResponse(Pair.with(root, str));
        }
        
    }

    /* Helper functions for key lookups */
    
    // retrieves the user leaf node given a specific key lookup
    private synchronized void handleKeyLookupProto(KeyLookup lookup)
        throws IOException{
        
        long epoch = lookup.getEpoch();
        if(epoch > curEpoch){
            epoch = curEpoch;
        }
        
        String username = lookup.getName();
        
        if(username.charAt(username.length()-1) == '/' ){
            username = username.substring(0,username.length()-1);
        }
        
        msgLog.log("Getting key for "+username+"... ");
        
        msgLog.log("SHA256 of name: " + ServerUtils.bytesToHex(ServerUtils.unameToIndex(username)));
	
        ServerUtils.Record r = getRecord(epoch);
        RootNode root = r.getRoot();	  
        
        UserLeafNode uln = getUlnFromTree(username, root);
        
        if(uln == null){
            msgLog.error(username + " not found...");
            sendSimpleResponse(ServerUtils.RespType.NAME_NOT_FOUND_ERR);
            return;
        }
        
        sendAuthPathResponse(uln, root);
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
        
        String username = changeReq.getName();
        
        if(username.charAt(username.length()-1) == '/' ){
            username = username.substring(0,username.length()-1);
        }
        
        ServerUtils.Record r = getRecord(curEpoch);
        RootNode root = r.getRoot();      
        
        // get the uln
        UserLeafNode uln = getUlnFromTree(username, root);  
        if(uln == null){
            msgLog.error(username + " not found...");
            sendSimpleResponse(ServerUtils.RespType.NAME_NOT_FOUND_ERR);
            return;
        }
        
        boolean allowsUnsignedKC = changeReq.hasAllowsUnsignedKeychange() ? changeReq.getAllowsUnsignedKeychange() : uln.allowsUnsignedKeychange();
        boolean allowsPublicLookup = changeReq.hasAllowsPublicLookup() ? changeReq.getAllowsPublicLookup() : uln.allowsPublicLookups();
        String newBlob = changeReq.hasNewBlob() ? changeReq.getNewBlob() : uln.getPublicKey();
        DSAPublicKey newChangeKey = changeReq.hasNewChangeKey() ? SignatureOps.makeDSAPublicKeyFromParams(changeReq.getNewChangeKey()) : uln.getChangeKey();
        
        ulnChange(username, newBlob, newChangeKey, allowsUnsignedKC, allowsPublicLookup, changeReq.toByteArray(), sig);
        serverLog.log("ulnChange: " + Arrays.toString(changeReq.toByteArray()));
        // If using a DB, insert the new user
        
        // Send a registration response so that the client knows when to check
        // that the changes were actually comitted
        this.regEpoch = curEpoch+CONFIG.EPOCH_INTERVAL;
        
        sendRegistrationRespResponse(regEpoch, CONFIG.EPOCH_INTERVAL);
    }
    
    /* Helper functions for ULN changes (with sig) */
    private synchronized void handleSignedULNChangeProto(SignedULNChangeReq signedReq)
        throws IOException{
        
        ULNChangeReq changeReq = signedReq.getReq();
        byte[] reqMsg = changeReq.toByteArray();
        
        String username = changeReq.getName();
        
        if(username.charAt(username.length()-1) == '/' ){
            username = username.substring(0,username.length()-1);
        }
        
        ServerUtils.Record r = getRecord(curEpoch);
        RootNode root = r.getRoot();      
        
        // get the uln
        UserLeafNode uln = getUlnFromTree(username, root);  
        if(uln == null){
            msgLog.error(username + " not found...");
            sendSimpleResponse(ServerUtils.RespType.NAME_NOT_FOUND_ERR);
            return;
        }
        
        // verify signature
        DSAPublicKey publicChangeKey = uln.getChangeKey();
        
        byte[] sig = ServerUtils.intListToByteArr(new ArrayList<Integer>(signedReq.getSigList()));
        if (!SignatureOps.verifySigFromDSA(reqMsg, sig, publicChangeKey)) {
            msgLog.log("Failed to verify message");
            msgLog.log("Failed sig said\n" + Arrays.toString(sig));
            sendSimpleResponse(ServerUtils.RespType.VERIFICATION_ERR);
            return;
        }
        
        // now pass to the unsigned version of the handler
        handleULNChangeProto(changeReq, sig);
    }
    
}
