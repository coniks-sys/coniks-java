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

import java.security.interfaces.DSAPublicKey;

import java.io.*;
import java.net.*;
import javax.net.ssl.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.PriorityQueue;
import java.util.Timer;
import java.util.TimerTask;
import java.util.Date;
import java.util.Scanner;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.lang.NumberFormatException;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.Executors;

import org.javatuples.*;
import com.google.protobuf.*;

import java.util.Arrays;

// TODO: Clean this up and structure more like client:
// separate "networking" from other functionality
// such as STR generation.

/** Implements the main CONIKS server operations:
 * interface to client, initiates Merkle tree rebuilding
 * and signed tree root (STR) generation.
 *
 *@author Marcela S. Melara (melara@cs.princeton.edu)
 *@author Michael Rochlin
 */
public class ConiksServer{

    // Must be passed in as args to the server!
    private static String configFileName;
    private static String logPath;
    private static int initNumUsers;
    private static boolean isFullOp;
    private static final int NUM_ARGS = 4; // ha, don't forget to set this to the right number

    // These configuration settings are now set in main
    private static ServerConfig CONFIG; 
    private static long curEpoch;

    //points to the head of the history list (newest record first)
    private static ServerUtils.Record curRecord = null; 
    private static int providerID; // meant to be SP ID to identify different SP's quickly
    private static Timer epochTimer = new Timer("epoch timer", false); // may wish to run as daemon later

    private static long initEpoch;
    
    private static int epochCounter = 0; 

    // this is a counter to be used to sort the uln changes so they happen in-order for the same person
    private static long ulnCounter = 0;

    // keeps all the new users on a day-by-day basis
    private static PriorityQueue<Triplet<byte[], UserLeafNode, Operation>> pendingQueue;   

    // logs are useful
    private static MsgHandlerLogger msgLog = null;
    private static TimerLogger timerLog = null;
    public static ServerLogger serverLog = null;

    /** Prints server status and error messages. 
     * Used primarily for testing mode.
     *
     *@param isErr indicates whether this is an error message
     *@param msg the status message to print
     */
    private static void printStatusMsg (boolean isErr, String msg) {
        String status = msg;
        if (isErr) {
            status = "Error: "+status;
        }

        System.out.println(status);
    }
    
      
    /** Adds a new name-to-key binding ({@code uname}, {@code pk})
     * to the pending registrations queue.
     */
    public static synchronized void register(String uname, String pk){            
        byte[] index = ServerUtils.unameToIndex(uname);
        UserLeafNode uln = new UserLeafNode(uname, pk, curEpoch+CONFIG.EPOCH_INTERVAL, 0, true, true, null, index);
        pendingQueue.add(Triplet.with(index, uln, (Operation)new Register()));
    }

    // Adds a ulnChange to the queue with the arguments
    public static synchronized void ulnChange(String uname, String newKey, DSAPublicKey kPrime, 
        boolean allowsUnsignedKC, boolean allowsPublicLookup, 
        byte[] msg, byte[] sig) {
        byte[] index = ServerUtils.unameToIndex(uname);
        UserLeafNode uln = new UserLeafNode(uname, newKey, curEpoch+CONFIG.EPOCH_INTERVAL, 0, true, true, kPrime, index);
        pendingQueue.add(Triplet.with(index, uln, 
            (Operation)new KeyChange(newKey, kPrime, allowsUnsignedKC, allowsPublicLookup, msg, sig, curEpoch, epochCounter++)));
    }
    
    /** Updates the server's STR history: inserts any pending registrations 
     * into the Merkle tree, takes a new snapshot of the whole directory,
     * and adds a new link to the hash chain.
     *
     *@return {@code true} if the update succeeded, {@code false} otherwise.
     */
    public static synchronized boolean updateHistory(){
      RootNode curRoot = null;
      boolean isGoodExit = true; // the exit status
      RootNode newRoot = null;

    	int toAdd = pendingQueue.size();
    	long timeUpdateStart = System.nanoTime();
      // msm: these two cases can probably be condensed
        if(curRecord != null){
            ServerUtils.Record r = curRecord;
            curRoot = r.getRoot();

            // this is just for debugging
            byte[] rootBytes = ServerUtils.convertRootNode(curRoot);

            timerLog.log("Root hash "+
                             ServerUtils.bytesToHex(ServerUtils.hash(rootBytes))
                           +"\n Prev: "+ServerUtils.bytesToHex(curRoot.getPrev()));
            
            newRoot = ServerOps.buildNextEpochTree(pendingQueue, curRoot,
                                                   curEpoch, CONFIG.EPOCH_INTERVAL);
	    
        }
        else {
            // we are in our first epoch
            // we add epoch_interval since we publish an hour after the current epoch
            newRoot = ServerOps.buildFirstEpochTree(pendingQueue, 
                                                    ServerUtils.hash(new byte[10]), 
                                                    curEpoch+CONFIG.EPOCH_INTERVAL);
        }

	// it's safe to clear the pending queue.
	pendingQueue.clear();

        if(newRoot != null){
            // now we can sign the new STR
            byte[] commSig = ServerOps.generateSTR(newRoot);
            
            if(commSig == null){
                return false;
            }

            // increment curEpoch for the new record
            curEpoch+=CONFIG.EPOCH_INTERVAL;

            // reset the uln counter
            ulnCounter = 0;
            
            // add the new STR to the linked list
            addNewRecord(newRoot, commSig);

            epochCounter++;
                
            byte[] rootBytes = ServerUtils.convertRootNode(newRoot);

            // At this point, the new root should be stored in a DB
            
            timerLog.log("Root hash " +
                         ServerUtils.bytesToHex(ServerUtils.hash(rootBytes)));
            
            return isGoodExit;
            
        }
        else {
            return false;
        }
    }

    /** Initialize the namespace: get the latest STR and root node from the 
     * database (if using one) and update the namespace internally (i.e. build the hash tree)
     * Because users are stored in lexicographic order, we can simply load them all at once, 
     * and load the appropriate previous root hash and epoch number from the db.
     * N.B. Designed for few restarts in mind.
     */
    private static void initNamespace(){
	PriorityQueue<Triplet<byte[], UserLeafNode, Operation>> initUsers = 
	    new PriorityQueue<Triplet<byte[], UserLeafNode, Operation>>(
		16384, new ServerUtils.PrefixComparator());

        serverLog.log("Beginning initNamespace()");

        // At this point, if we're using a DB, we want to check if we already have
        // a commitment history stored in the DB
        // if so, retrieve the latest commitment and root node stored in the DB
     
        // for demo purposes we're just going to create a bunch of dummy users 

        initEpoch = curEpoch;
	
        long handled = 0;
        long size = initNumUsers;
        long batchSize = size/10; // unused right now, but it's here for future versions
        UserTreeBuilder utb = ServerOps.startBuildInitTree(ServerUtils.hash(new byte[10]), 
                                                           initEpoch);
        
        RootNode initRoot = null;    
        // add <size> dummy users
        for (int i = 0 ; i < size; i++){
            String userId = String.format("test-%d", i);
            String pubKey = "(dsa  (p #test-10000007712ECAF91762ED4E46076D846624D2A71C67A991D1FEA059593163C2B19690B1A5CA3C603F52A62D73BB91D521BA55682D38E3543CC34E384420AA32CFF440A90D28A6F54C586BB856460969C658B20ABF65A767063FE94A5DDBC2D0D5D1FD154116AE7039CC4E482DCF1245A9E4987EB6C91B32834B49052284027#) (q #00B84E385FA6263B26E9F46BF90E78684C245D5B35#) (g #77F6AA02740EF115FDA233646AAF479367B34090AEC0D62BA3E37F793D5CB995418E4F3F57F31612561A4BEA41FAC3EE05679D90D2F79A581905E432B85F4C109164EB7846DC9C3669B013D67063747ABCC4B07EAA4AC44D9DE9FC2A349859994DB683DFC7784D0F1DF1DA25014A40D8617E3EC94D8DB8FBBBC37A5C5AAEE5DC#) (y #4B41A8AA7B6F23F740DEF994D1A6582E00E4B821F65AC30BDC6710CD6111FA24DE70EACE6F4A92A84038D4B928D79F6A0DF35F729B861A6713BECC934309DE0822B8C9D2A6D3C0A4F0D0FB28A77B0393D72568D72EE60C73B2C5F6E4E1A1347EDC20AC449EFF250AC1C251E16403A610DB9EB90791E63207601714A78679283))";
            long epochAdded = initEpoch;
            byte[] index = ServerUtils.unameToIndex(userId);
            
            UserLeafNode uln = new UserLeafNode(userId, pubKey, epochAdded, 0, index);
            initUsers.add(Triplet.with(index, uln, (Operation)new Register()));
            
        }
        initRoot = utb.extendTree(initUsers);
         
        if(initRoot == null) {
            if (isFullOp) {
                serverLog.error("An error occured while trying to build the initial tree");
            }
            else {
                printStatusMsg(true, "An error occured while trying to build the initial tree");
            }
            return;
        }
        
        initUsers.clear();

        utb.clearTemps();
            
        byte[] commSig = ServerOps.generateSTR(initRoot);

        if (isFullOp) {
            serverLog.log("initial root epoch: "+initRoot.getEpoch()+"\n"+
                          "comm sig: "+ServerUtils.bytesToHex(commSig));
            serverLog.log("epoch len: " + CONFIG.EPOCH_INTERVAL);
        }
        else {
            printStatusMsg(false, "initial root epoch: "+initRoot.getEpoch());
            printStatusMsg(false, "epoch len: " + CONFIG.EPOCH_INTERVAL);
        }
        curRecord = new ServerUtils.Record(initRoot,
                                           initRoot.getEpoch(), commSig, null);
        epochCounter++;

        if (isFullOp) {
            serverLog.log("Namespace initialized with "+size+" dummy users.");
        }
        else {
            printStatusMsg(false, "Namespace initialized with "+size+" dummy users.");
        }
    }
    
    /** Adds the new root node {@code newRoot} and STR {@code str} 
     * as a "record" in the linked 
     * list representing the STR hash chain. This function is usually
     * called after updating the Merkle tree.
     */
    private static synchronized void addNewRecord(RootNode newRoot, byte[] str) {
        
        ServerUtils.Record newRecord = new ServerUtils.Record(newRoot, 
                                                              curEpoch, str, curRecord);
      	if (curRecord != null){
      	    // let's not keep more than one back in memory
      	    curRecord.setPrev(null);
      	}

        // reassign pointer
        curRecord = newRecord;	
    }

    /** Retrieves the "record" for epoch {@code ep} from the linked
     * list representing the STR hash chain.
     *
     *@return The record for epoch {@code ep}.
     *@throws An {@code UnsupportedOperationException} in case the 
     * head of the list is reached before the requested record is found.
     */
    public static synchronized ServerUtils.Record getRecord(long ep){
        ServerUtils.Record runner = curRecord;
        
        while(runner.getRoot().getEpoch() > ep && runner != null){                
                // need to check if we reached the head of the list
                if (runner.getPrev() == null) {
                    throw new UnsupportedOperationException("reached the head of the list!");
                }
                else{
                    runner = runner.getPrev();
                }
        }
        
        return runner;
    }
    
    /** Sets up several configurations and begins listening for
     * incoming connections from CONIKS clients.
     *<p>
     * Usage:
     * {@code ./coniks_server.sh <start | test | stop | clean>}
     */
    public static void main(String[] args){
        
        if (args.length != NUM_ARGS) {
            System.out.println("Need "+(NUM_ARGS-1)+" arguments: CONIKS_SERVERCONFIG, CONIKS_SERVERLOGS, and CONIKS_INIT_SIZE");
            System.out.println("The run script may expect these to be passed as env vars, make sure to export these before running the run script again.");
            System.exit(-1);
        }

        initNumUsers = 0;
        File configFile = null;
        try {
            configFileName = args[0];
            configFile = new File(configFileName);

            logPath = args[1];
            File logDir = new File(logPath);

            if (!configFile.exists() || !logDir.isDirectory()) {
                throw new FileNotFoundException();
            }
            
            initNumUsers = Integer.parseInt(args[2]);

            String opMode = args[3];
            if (opMode.equalsIgnoreCase("full")) {
                isFullOp = true;
            }
            else if (opMode.equalsIgnoreCase("test")) {
                isFullOp = false;
            }
            else {
                System.out.println("Unknown operation mode: "+opMode);
                System.exit(-1);
            }
        }
        catch (NumberFormatException e) {
            System.out.println("CONIKS_INIT_SIZE must be an integer.");
            System.exit(-1);
        }
        catch (FileNotFoundException e) {
            System.out.println("The path you entered for CONIKS_SERVERCONFIG or CONIKS_SERVERLOGS doesn't exist.");
            System.exit(-1);
        }

        // read in the server config
        CONFIG = new ServerConfig();
        
        // false indictaes an error, so exit
        if (!CONFIG.readServerConfig(configFile, isFullOp)) {
            System.exit(-1);
        }
        
        // set some more configs
        curEpoch = CONFIG.STARTUP_TIME;
        msgLog = MsgHandlerLogger.getInstance(logPath+"/msg-handler-%g");
        timerLog = TimerLogger.getInstance(logPath+"/epoch-timer-%g");
        serverLog = ServerLogger.getInstance(logPath+"/server-%g");

        pendingQueue = new PriorityQueue<Triplet<byte[], UserLeafNode, Operation>>( 
	    16384, new ServerUtils.PrefixComparator());

        System.setProperty("javax.net.ssl.keyStore", CONFIG.KEYSTORE_PATH);
        System.setProperty("javax.net.ssl.keyStorePassword", CONFIG.KEYSTORE_PWD);

        // this is needed to set up the SSL connection
        if (isFullOp) {
            System.setProperty("javax.net.ssl.trustStore", CONFIG.TRUSTSTORE_PATH);
            System.setProperty("javax.net.ssl.trustStorePassword", CONFIG.TRUSTSTORE_PWD);
        }

        SignatureOps.initSignatureOps(CONFIG);
        initNamespace(); // initializes the namespace with latest stored snapshot and all registered users
        
        EpochTimerTask epochSnapshotTaker = new EpochTimerTask();
        
    	ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
        scheduler.scheduleWithFixedDelay(epochSnapshotTaker, 
    					 CONFIG.EPOCH_INTERVAL, 
    					 CONFIG.EPOCH_INTERVAL,
    					 TimeUnit.MILLISECONDS);

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
                
                ServerThread th = new ServerThread(c);
                th.start();
                
            }
        }
        catch(Exception e){
            serverLog.error("Exception: " + e.getMessage());
	    e.printStackTrace();
            System.exit(-1);
        }
        
    }
    
    /** Implements a TimerTask that updates the STR history every epoch.
     */
    private static class EpochTimerTask implements Runnable {

        private DataOutputStream dout;

        public void run() {
	    timerLog.log("Timer task started.");
            boolean isGood = updateHistory();

            if(isGood){
                if (isFullOp) {
                    timerLog.log("STR taken");
                }
                else {
                    printStatusMsg(false, "Next epoch");
                }
            }
            else{
                 // Need to figure out what to do in case it fails
                if (isFullOp) {
                    timerLog.error("An error occurred while updating the history");
                }
                else {
                    printStatusMsg(true, "An error occurred while updating the history");
                }
                throw new UnsupportedOperationException("Something went wrong in updateHistory()");
            }
        }

    }

    /** A Thread that attempts a connection with a CONIKS client
     *
     * @author Marcela Melara
     *
     */
    private static class ServerThread extends Thread{
        
        private Socket clientSocket;
        private DataInputStream din;
        private DataOutputStream dout;
        private long regEpoch;
        private int msgType;
         
        /** Constructor of a ServerThread
         *
         * @param s the client socket
         */
        public ServerThread(Socket c){
            
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
            
            //attempt connection to the client
            try{	
                din = new DataInputStream(clientSocket.getInputStream());
                dout = new DataOutputStream(clientSocket.getOutputStream());

                // this will also get the message type
                AbstractMessage clientMsg = receiveMsgProto();

                if (clientMsg == null) {
                    sendSimpleResponse(ServerUtils.RespType.MALFORMED_ERR);
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
                
                clientSocket.close();
                
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

        } //ends run()

        /* Message handlers */
        
        /** Receives a protobuf message from the client and checks that
         * the message is correctly formatted for the expected message type.
         * The caller is responsible for handling the exact message type(s).
         *
         *@return The specific protobuf message according to the message type
         * indicated by the client.
         */
        private synchronized AbstractMessage receiveMsgProto() {
            
            try {
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

            // unexpected message type from the client
            return null;
        }

        private synchronized void handleRegistrationProto(Registration reg) 
            throws IOException{
            msgLog.log("Handling registration message... ");

            if(!reg.hasBlob()){
                msgLog.log("Malformed registration message");
                sendSimpleResponse(ServerUtils.RespType.MALFORMED_ERR);
                return;
            }
           
            String name =reg.getName();

            // want to check first whether the name already 
            // exists in the database before we register, if it does, reply with error
            ServerUtils.Record r = getRecord(curEpoch);
            RootNode root = r.getRoot();

            UserLeafNode uln = getUlnFromTree(name, root);

            if (uln != null) {
                msgLog.error("Found: "+
                             ServerUtils.bytesToHex(ServerUtils.unameToIndex(uln.getUsername()))+
                             "\n"+uln.getUsername()+" found when trying to insert "+name);
                sendSimpleResponse(ServerUtils.RespType.NAME_EXISTS_ERR);
                return;
            }

            this.regEpoch = curEpoch+CONFIG.EPOCH_INTERVAL;
                      
            // If using a DB, insert the new user

            // we register the user in the pendingQueue
            register(name, reg.getBlob());

            sendRegistrationRespResponse(regEpoch, CONFIG.EPOCH_INTERVAL);
        
        }

        /* Helper functions for commitment requests */

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

                sendCommitmentResponse(Pair.with(root, str));
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

        // traverses down the tree until we reach the requested user leaf node
        // msm: this pretty much repeats the traversal in ServerOps.generateAuthPathProto
        // so we should really find a way to remove this redundancy
        private synchronized UserLeafNode getUlnFromTree(String username,
                                                         RootNode root) {

            // traverse based on lookup index for this name
            byte[] lookupIndex = ServerUtils.unameToIndex(username);
            
            // not worth doing this recursively
            int curOffset = 0;
            TreeNode runner = root;
            
            msgLog.log("searching for: "+ServerUtils.bytesToHex(lookupIndex));

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

        /* Message sending functions */

        // send back a simple server response based on the result of the request
        private synchronized void sendSimpleResponse(ServerUtils.RespType reqResult){
            msgLog.log("Sending simple server response... ");
            try{              
                ServerResp respMsg = buildServerRespMsg(reqResult);
                dout.writeByte(MsgType.SERVER_RESP);
                respMsg.writeDelimitedTo(dout);
                dout.flush();
                din.close();
                dout.close();        
            }
            catch(IOException e){
                msgLog.error("Something went wrong while trying to send a message to the client");
            }
        }

        // send back the commitment returned for the commitment request
        private synchronized void sendCommitmentResponse(Pair<RootNode, 
                                                         byte[]> commPair){
            msgLog.log("Sending commitment response... ");
            try{              
                Commitment comm = buildCommitmentMsg(commPair.getValue0(), 
                                                     commPair.getValue1());
                byte[] rootBytes = ServerUtils.convertRootNode(commPair.getValue0());
                msgLog.log("Root hash "+
                             ServerUtils.bytesToHex(ServerUtils.hash(rootBytes))
                           +"\n Epoch: "+commPair.getValue0().getEpoch()
                           +"\n Prev: "+ServerUtils.bytesToHex(commPair.getValue0().getPrev()));
                dout.writeByte(MsgType.COMMITMENT);
                comm.writeDelimitedTo(dout);
                dout.flush();
                din.close();
                dout.close();                
            }
            catch(IOException e){
                msgLog.error("Something went wrong while trying to send a message to the client");
            }
        }

        // send back the initial epoch and epoch interval for the newly registered user, who will cache this info
        private synchronized void sendRegistrationRespResponse(long initEpoch, int epochInterval){
            msgLog.log("Sending registration response... ");
            try{              
                RegistrationResp regResp = buildRegistrationRespMsg(initEpoch, epochInterval);
                dout.writeByte(MsgType.REGISTRATION_RESP);
                regResp.writeDelimitedTo(dout);
                dout.flush();
                din.close();
                dout.close();                
            }
            catch(IOException e){
                msgLog.error("Something went wrong while trying to send a message to the client");
            }
        }

        // send back the authentication path based on the key lookup
        private synchronized void sendAuthPathResponse(UserLeafNode uln, RootNode root){
            msgLog.log("Sending authentication path response... ");
            try{              
                AuthPath authPath = buildAuthPathMsg(uln, root);
                dout.writeByte(MsgType.AUTH_PATH);
                authPath.writeDelimitedTo(dout);
                dout.flush();
                din.close();
                dout.close();               
            }
            catch(IOException e){
                msgLog.error("Something went wrong while trying to send a message to the client");
            }
        }

        /* Message building functions */

        // create the simple server response message
        private ServerResp buildServerRespMsg(ServerUtils.RespType respType){
            ServerResp.Builder respMsg = ServerResp.newBuilder();
            switch(respType){
            case SUCCESS:
                respMsg.setMessage(ServerResp.Message.SUCCESS);
                break;
            case NAME_EXISTS_ERR:
                respMsg.setMessage(ServerResp.Message.NAME_EXISTS_ERR);
                break;
            case NAME_NOT_FOUND_ERR:
                respMsg.setMessage(ServerResp.Message.NAME_NOT_FOUND_ERR);
                break;
            case MALFORMED_ERR:
                respMsg.setMessage(ServerResp.Message.MALFORMED_ERR);
                break;
            case COMMITMENT_RESP:
                respMsg.setMessage(ServerResp.Message.COMMITMENT_RESP);
                break;
            case AUTH_PATH:
                respMsg.setMessage(ServerResp.Message.AUTH_PATH);
                break;
            case VERIFICATION_ERR:
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
        
    } //ends ServerThread class
    
} // ends class
