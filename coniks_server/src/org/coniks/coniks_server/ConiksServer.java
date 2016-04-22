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

import java.util.ArrayList;
import java.util.Timer;
import java.util.PriorityQueue;
import java.util.TimerTask;
import java.util.Date;
import java.util.Scanner;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.lang.NumberFormatException;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.Executors;

import com.google.protobuf.*;
import org.javatuples.*;
import java.util.Arrays;

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

    private static int providerID; // meant to be SP ID to identify different SP's quickly
    private static Timer epochTimer = new Timer("epoch timer", false); // may wish to run as daemon later

    private static long initEpoch;

    // logs are useful
    public static MsgHandlerLogger msgLog = null;
    private static TimerLogger timerLog = null;
    public static ServerLogger serverLog = null;

    /** Initialize the directory: get the latest root node from the 
     * database (if using one) and update the directory internally (i.e. build the hash tree)
     * Because users are stored in lexicographic order, we can simply load them all at once.
     * N.B. Designed for few restarts in mind.
     */
    private static RootNode initDirectory(){
	PriorityQueue<Triplet<byte[], UserLeafNode, Operation>> initUsers = 
	    new PriorityQueue<Triplet<byte[], UserLeafNode, Operation>>(
		16384, new ServerUtils.PrefixComparator());

        serverLog.log("Beginning initNamespace()");

        // At this point, if we're using a DB, we want to check if we already have
        // a commitment history stored in the DB
        // if so, retrieve the latest commitment and root node stored in the DB
     
        // for demo purposes we're just going to create a bunch of dummy users 	
        long handled = 0;
        long size = initNumUsers;
        long batchSize = size/10; // unused right now, but it's here for future versions
        
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
        initRoot = TreeBuilder.copyExtendTree(null, initUsers);
        
        initUsers.clear();

        if (isFullOp) {
            serverLog.log("Directory initialized with "+size+" dummy users.");
        }
        else {
            ServerUtils.printStatusMsg(false, "Directory initialized with "+size+" dummy users.");
        }

        return initRoot;
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
        
        // false indictaes an error, so exit
        if (!ServerConfig.readServerConfig(configFile, isFullOp)) {
            System.exit(-1);
        }
        
        // set some more configs
        initEpoch = ServerConfig.STARTUP_TIME;
        msgLog = MsgHandlerLogger.getInstance(logPath+"/msg-handler-%g");
        timerLog = TimerLogger.getInstance(logPath+"/epoch-timer-%g");
        serverLog = ServerLogger.getInstance(logPath+"/server-%g");

        System.setProperty("javax.net.ssl.keyStore", ServerConfig.KEYSTORE_PATH);
        System.setProperty("javax.net.ssl.keyStorePassword", ServerConfig.KEYSTORE_PWD);

        // this is needed to set up the SSL connection
        if (isFullOp) {
            System.setProperty("javax.net.ssl.trustStore", ServerConfig.TRUSTSTORE_PATH);
            System.setProperty("javax.net.ssl.trustStorePassword", ServerConfig.TRUSTSTORE_PWD);
        }

        RootNode initRoot = initDirectory(); // initializes the directory

        // check that we got a good first tree
        if(initRoot == null) {
            if (isFullOp) {
                serverLog.error("An error occured while trying to build the initial tree");
            }
            else {
                ServerUtils.printStatusMsg(true, "An error occured while trying to build the initial tree");
            }
            // just bail
            System.exit(-1);
        }

        // init the history
         if (!ServerHistory.initHistory(initRoot, initEpoch, 0, 
                                       new byte[ServerUtils.HASH_SIZE_BYTES])) {
            ServerUtils.printStatusMsg(true, "Error initializing the history");
            System.exit(-1);
         }
        
        EpochTimerTask epochSnapshotTaker = new EpochTimerTask();
        
    	ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
        scheduler.scheduleWithFixedDelay(epochSnapshotTaker, 
    					 ServerConfig.EPOCH_INTERVAL, 
    					 ServerConfig.EPOCH_INTERVAL,
    					 TimeUnit.MILLISECONDS);

        ServerMessaging.listenForRequests(isFullOp);
        
    }
    
    /** Implements a TimerTask that updates the STR history every epoch.
     */
    private static class EpochTimerTask implements Runnable {

        public void run() {
	    timerLog.log("Timer task started.");
            RootNode nextRoot = DirectoryOps.updateDirectory();

            // check that we got a good first tree
            if(nextRoot == null) {
                if (isFullOp) {
                    serverLog.error("An error occured while trying to update the tree");
                }
                else {
                    ServerUtils.printStatusMsg(true, "An error occured while trying to update the tree");
                }
                // let's not quite bail here
                throw new UnsupportedOperationException("Next root was null");
            }

            // this should approximately be EPOCH_INTERVAL millis since the last call
            long nextEpoch = System.currentTimeMillis();

            SignedTreeRoot nextSTR = TransparencyOps.generateNextSTR(nextRoot, nextEpoch);

            if (!ServerHistory.updateHistory(nextSTR)) {
                if (isFullOp) {
                    serverLog.error("An error occured while trying to update the tree");
                }
                else {
                    ServerUtils.printStatusMsg(true, "An error occured while trying to update the tree");
                }
                // let's not quite bail here
                throw new UnsupportedOperationException("Next STR was null or malformed");
            }
        }
        
    }
    
}
