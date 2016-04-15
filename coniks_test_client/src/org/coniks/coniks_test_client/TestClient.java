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

import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import javax.crypto.*;
import java.util.Random;
import java.math.BigInteger;
import java.util.Scanner;
import java.io.File;
import java.io.FileNotFoundException;
import java.lang.NumberFormatException;

import com.google.protobuf.*;
import org.coniks.coniks_common.C2SProtos.RegistrationResp;
import org.coniks.coniks_common.C2SProtos.AuthPath;
import org.coniks.coniks_common.UtilProtos.ServerResp;

/** Implementation of a simple CONIKS test client
 * that simply displays how each component of the
 * protocol works.
 * The client is completely agnostic to the underlying format
 * of the messages sent to the server (it only needs to know 
 * whether it's using protobufs (TODO: or json)).
 * 
 *@author Marcela S. Melara (melara@cs.princeton.edu)
 *@author Michael Rochlin
 */
public class TestClient {

    // Must be passed in as args to the client
    private static String configFileName;
    private static String logPath;
    private static String server;
    private static boolean isFullOp;
    private static final int NUM_ARGS = 4; // ha, don't forget to set this to the right number

    // since we're only creating dummy users, use this 
    // DSA-looking string as the test public key
    private static final String FAKE_PK_BASE = "(dsa \n (p #7712ECAF91762ED4E46076D846624D2A71C67A991D1FEA059593163C2B19690B1A5CA3C603F52A62D73BB91D521BA55682D38E3543CC34E384420AA32CFF440A90D28A6F54C586BB856460969C658B20ABF65A767063FE94A5DDBC2D0D5D1FD154116AE7039CC4E482DCF1245A9E4987EB6C91B32834B49052284027#)\n (q #00B84E385FA6263B26E9F46BF90E78684C245D5B35#)\n (g #77F6AA02740EF115FDA233646AAF479367B34090AEC0D62BA3E37F793D5CB995418E4F3F57F31612561A4BEA41FAC3EE05679D90D2F79A581905E432B85F4C109164EB7846DC9C3669B013D67063747ABCC4B07EAA4AC44D9DE9FC2A349859994DB683DFC7784D0F1DF1DA25014A40D8617E3EC94D8DB8FBBBC37A5C5AAEE5DC#)\n (y #4B41A8AA7B6F23F740DEF994D1A6582E00E4B821F65AC30BDC6710CD6111FA24DE70EACE6F4A92A84038D4B928D79F6A0DF35F729B861A6713BECC934309DE0822B8C9D2A6D3C0A4F0D0FB28A77B0393D72568D72EE60C73B2C5F6E4E1A1347EDC20AC449EFF250AC1C251E16403A610DB9EB90791E63207601714A786792835#)";
   
    /** Creates a dummy public key which is a deterministic
     * function of the {@code username}.
     *
     *@return The dummy public key as a String.
     */
    private static String createPkFor(String username){
        return String.format(FAKE_PK_BASE, username);
    }

    /** Returns the server error code corresponding to the
     * given server response proto message.
     *
     *@param serverMsg the simple server message
     *@return the error code corresponding to the simple server message
     */
    private static int getServerErr (ServerResp serverResp) {

        ServerResp.Message respType = serverResp.getMessage();

        int serverErr = ServerErr.SUCCESS;

        switch(respType) {
        case SUCCESS:
            serverErr = ServerErr.SUCCESS;
            break;
        case NAME_EXISTS_ERR:
            serverErr = ServerErr.NAME_EXISTS_ERR;
            break;
        case NAME_NOT_FOUND_ERR:
            serverErr = ServerErr.NAME_NOT_FOUND_ERR;
            break;
        case MALFORMED_ERR:
            serverErr = ServerErr.MALFORMED_CLIENT_MSG_ERR;
            break;
        case VERIFICATION_ERR:
            serverErr = ServerErr.SIGNED_CHANGE_VERIF_ERR;;
            break;
        default:
            serverErr = ServerErr.SERVER_ERR;
            break;                
        }

        return serverErr;

    }

    /** Perfoms the CONIKS registration protocol with {@code server}
     * for the dummy user {@code username}.
     *
     *@return NO_ERR (0) if the registration was successful, an error code
     * otherwise.
     */
    public static int register (String username, String server) {
        String pk = createPkFor(username);
        
        ConiksClient.sendRegistrationProto(username, pk, server);
        
        AbstractMessage serverMsg = ConiksClient.receiveRegistrationRespProto();

        if (serverMsg == null) {
            return ServerErr.MALFORMED_SERVER_MSG_ERR;
        }
        else if (serverMsg instanceof ServerResp) {
            return getServerErr((ServerResp)serverMsg);
        }
        else {
            // TODO: for now just return SUCCESS
            // eventually we want to process the registration response
            return ServerErr.SUCCESS;
        }

    }

    /** Looks up the public key for the given {@code username}
     * at {@code server}, and verifies the returned proof of inclusion
     * (authentication path)  if the name exists.
     *
     *@return NO_ERR (0) if the registration was successful, an error code
     * otherwise.
     */
    public static int lookup (String username, String server) {
        long epoch = System.currentTimeMillis();

        ConiksClient.sendKeyLookupProto(username, epoch, server);

        AbstractMessage serverMsg = ConiksClient.receiveAuthPathProto();

        if (serverMsg == null) {
            return ServerErr.MALFORMED_SERVER_MSG_ERR;
        }
        else if (serverMsg instanceof ServerResp) {
            return getServerErr((ServerResp)serverMsg);
        }
        else if (serverMsg instanceof AuthPath) {
            AuthPath authPath = (AuthPath)serverMsg;

            // TODO, we'll want to get the latest STR here

            // we got an auth path back, so verify it
            int result = ConsistencyChecks.verifyDataBindingProto(authPath, null);

            // TODO: we'll want to potentially store the looked up key
            // if it checks out

            return result;
        }
        else {
            // we received some unexpected server message
            // receiveAuthPathProto gave us back something bad
            ConiksClient.clientLog.error("Got bad protobuf type from receiveAuthPath()");
            return ClientUtils.INTERNAL_CLIENT_ERR;
        }

    }

    /** Performs a key change by randomly changing the user's data-blob
     * and signing and sending a new changekey 
    */
    public static boolean doSignedKeyChange(String username, String server) {
        SignatureOps.initSignatureOps(ConiksClient.CONFIG);
        DSAPrivateKey prKey = SignatureOps.unsafeLoadDSAPrivateKey(username);
        System.out.print(username + " : " + prKey + " ");
        System.out.printf("x: %s\n", prKey.getX());

        String newBlob = "(signed changed: " + new BigInteger(50, new Random()).toString(32);
        KeyPair kp = KeyOps.generateDSAKeyPair();
        ConiksClient.sendSignedULNChangeReqProto(username, newBlob, (DSAPublicKey) kp.getPublic(),
                                                 false, true, prKey, server);

        if (ConiksClient.receiveRegistrationRespProto() == null) {
            return false;
        }

        SignatureOps.unsafeSaveDSAKeyPair(kp, username);

        return true;

    }

    /** performs an unsigned key change. Should fail if the username
     * requires signed key changes. 
     */
    public static boolean doUnsignedKeyChange(String username, String server) {
        String newBlob = "(unsigned changed: " + new BigInteger(50, new Random()).toString(32);
        KeyPair kp = KeyOps.generateDSAKeyPair();
        ConiksClient.sendULNChangeReqProto(username, newBlob, (DSAPublicKey) kp.getPublic(),
                                                 true, true, server);

        if (ConiksClient.receiveRegistrationRespProto() == null) {
            return false;
        }

        SignatureOps.unsafeSaveDSAKeyPair(kp, username);

        return true;
    }

    /** changes a user to allow unsigned key changes */
    public static boolean doChangeToAllowsUnsigned(String username, String server) {
        SignatureOps.initSignatureOps(ConiksClient.CONFIG);
        DSAPrivateKey prKey = SignatureOps.unsafeLoadDSAPrivateKey(username);

        String newBlob = "(allows changed: " + new BigInteger(50, new Random()).toString(32);
        KeyPair kp = KeyOps.generateDSAKeyPair();
        ConiksClient.sendSignedULNChangeReqProto(username, newBlob, (DSAPublicKey) kp.getPublic(),
                                                 true, true, prKey, server);

        if (ConiksClient.receiveRegistrationRespProto() == null) {
            return false;
        }

        SignatureOps.unsafeSaveDSAKeyPair(kp, username);

        return true;

    }

    /** Prints the usage of the TestClient.
     */
    private static void usage() {
        System.out.println("valid operations: REGISTER, LOOKUP, SIGNED, UNSIGNED, CHANGES, MIXED");
    }

    /** Template for an error message.
     *
     *@param msg The error message to print.
     */
    private static void printErr (String msg) {
        System.out.println("Error: "+msg);
    }

    /** Prints an error message for the given user and the given error code.
     *
     *@param err the error code for which to print the error message
     *@param uname the username for which the error occurred
     */
    private static void printErrMsg (int err, String uname) {

        switch(err) {
        case ServerErr.SUCCESS:
            // don't print anything for a successful operation
            break;
        case ConsistencyErr.CHECK_PASSED:
            // don't print anything here either
            break;
        case ClientUtils.INTERNAL_CLIENT_ERR:
            printErr("Some internal client error occurred while processing user "+uname+". Check the logs for details.");
            break;
        case ServerErr.INTERNAL_SERVER_ERR:
            printErr("The server experienced some internal error. Current user: "+uname);
            break;
        case ServerErr.NAME_EXISTS_ERR:
            printErr("Couldn't register the name "+uname+" because it already exists.");
            break;
        case ServerErr.NAME_NOT_FOUND_ERR:
            printErr("Couldn't find the name "+uname+".");
            break;
        case ServerErr.MALFORMED_CLIENT_MSG_ERR:
            printErr("The server received a malformed message for user "+uname);
            break;
        case ServerErr.MALFORMED_SERVER_MSG_ERR:
            printErr("Received a malformed server message. Current user: "+uname);
        case ServerErr.SIGNED_CHANGE_VERIF_ERR:
            printErr("The server could not verify the signed data change for user "+uname+".");
            break;
        case ServerErr.SERVER_ERR:
            printErr("Some other server error occurred. Current user: "+uname);
            break;
        case ConsistencyErr. BAD_BINDING_ERR:
            printErr("Unexpected key for user "+uname+".");
            break;
        case ConsistencyErr.BAD_STR_ERR:
            printErr("Inconsistent signed tree roots. Current user: "+uname);
            break;
        case ConsistencyErr.BAD_SERVER_SIG_ERR:
            printErr("Could not verify the server's identity. Current user: "+uname);
            break;
        default:
            printErr("Some unknown server error occurred.");
            break;                
        }

    }

    /** Checks whether the given operation is valid.
     *
     *@param op the operation to be checked.
     *@return {@code true} if it's valid, {@code false} otherwise.
     */
    private static boolean isValidOperation (String op) {
         if (op.equalsIgnoreCase("LOOKUP") || 
            op.equalsIgnoreCase("REGISTER") || 
            op.equalsIgnoreCase("SIGNED") || 
            op.equalsIgnoreCase("UNSIGNED") ||
            op.equalsIgnoreCase("CHANGES") ||
            op.equalsIgnoreCase("MIXED")) {
             return true;
         }
         else {
             return false;
         }
    }

    /** Performs the given operation {@code numUsers} times, starting
     * at user number {@code offset}.
     *
     *@param op the operation to perform
     *@param numUsers the number of users for which to do the operation
     *@param offset the user number at which to start
     */
    private static void doOperation (String op, int numUsers, int offset) {
        // print the status
        if (numUsers == 1) {
            System.out.print("Performing "+op+" for user test-"+offset);
        }
        else if (numUsers > 1) {
            System.out.print("Performing "+op+" for users test-"+offset+" thru test-"+(offset+numUsers-1));
        }


        for (int i = 0; i < numUsers; i++){
            // this is just a nicety to give the user some sense of progress
            if (numUsers <= 5 && i == 0) {
                System.out.print("...");
            }
            else if (numUsers >= 6  && numUsers <= 49 && i % (1+ (numUsers / 6)) == 0) {
                System.out.print(".");
            }
            if (numUsers >= 50  && numUsers <= 99 && i % (1 + (numUsers / 25)) == 0) {
                System.out.print(".");
            }
            else if (numUsers >= 100 && i % (1+ (numUsers / 50)) == 0) {
                System.out.print(".");
            }

            String uname = "test-"+(offset+i);

            int error = 0;
            
            if(op.equalsIgnoreCase("LOOKUP")){
                error = lookup(uname, server);
            }
            else if (op.equalsIgnoreCase("REGISTER")){
                error = register(uname, server);
            }
            else if (op.equalsIgnoreCase("SIGNED")) {
                if (!doSignedKeyChange(uname, server)) {
                    System.out.println("An error occured");
                }
            }
            else if (op.equalsIgnoreCase("UNSIGNED")) {
                if (!doUnsignedKeyChange(uname, server)) {
                    System.out.println("An error occured");
                }

            }
            else if (op.equalsIgnoreCase("CHANGES")) {
                if (!doChangeToAllowsUnsigned(uname, server)) {
                    System.out.println("An error occured");
                }

            }
            else if (op.equalsIgnoreCase("MIXED")) {
                if (!doSignedKeyChange(uname, server)) {
                    System.out.println("An error occured");
                }
            }
        
            // if we got an error, print a new line so the error msg doesn't
            // appear next to the progress dots
            if (error != ServerErr.SUCCESS && error != ConsistencyErr.CHECK_PASSED) {
                System.out.println();
            }

            printErrMsg(error, uname);
        }
        System.out.println(" done!");
    }

    /** Prompts the user to perform a CONIKS operation for one or more users.
     */
    public static void main(String[] args){

        if (args.length != NUM_ARGS) {
            System.out.println("Need "+(NUM_ARGS-1)+" arguments: CONIKS_CLIENTCONFIG CONIKS_CLIENTLOGS and SERVER");
            System.out.println("Check run script for more info.");
            System.exit(-1);
        }

        File configFile = null;
        try {
            configFileName = args[0];
            configFile = new File(configFileName);

            logPath = args[1];
            File logDir = new File(logPath);

            if (!configFile.exists() || !logDir.isDirectory()) {
                throw new FileNotFoundException();
            }

            server = args[2];

            String opMode = args[NUM_ARGS-1];
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
        catch (FileNotFoundException e) {
            System.out.println("The path you entered for CONIKS_CLIENTCONFIG doesn't exist.");
            System.exit(-1);
        }

        // read in the client config
        ConiksClient.CONFIG = new ClientConfig();

        // false indictaes an error, so exit
        if (!ConiksClient.CONFIG.readClientConfig(configFile, isFullOp)) {
            System.exit(-1);
        }

        // setup the logging
        ConiksClient.setupLogging(logPath);

        // set the client's operating mode
        ConiksClient.setOpMode(isFullOp);

        String cont = "y";

        Scanner scanner = new Scanner(System.in);

        if (isFullOp) {
            // this is needed to enable the client to communicate using SSL
            ConiksClient.setDefaultTruststore();
        }

        // this loops prompts the users to enter the command, the number of users to run it for
        // and the offset
        while (!cont.equalsIgnoreCase("n")) {

            //  prompt for the user's name
            System.out.print("Enter the next operation (or h for help): ");
            
            // get their input as a String
            String op = scanner.next();

            if (op.equalsIgnoreCase("h")) {
                usage();
            }
            else if (isValidOperation(op)) {
                System.out.print("Enter the number of users for this operation: ");

                int numUsers = 1;

                try {
                    numUsers = Integer.parseInt(scanner.next());

                    while (numUsers < 1) {
                        System.out.println("the number of users must be a positive integer.");
                        System.out.print("Enter the number of users for this operation: ");
                        numUsers = Integer.parseInt(scanner.next());
                    }
                }
                catch (NumberFormatException e) {
                    System.out.println("malformed number.");
                    break;
                }

                System.out.print("Enter the first user number for this operation: ");

                int offset = 0;

                try {
                    offset = Integer.parseInt(scanner.next());

                    while (offset < 0) {
                        System.out.println("the user number can't be a negative number.");
                        System.out.print("Enter the first user number for this operation: ");
                        offset = Integer.parseInt(scanner.next());
                    }
                }
                catch (NumberFormatException e) {
                    System.out.println("malformed number.");
                    break;
                }

                // do the operation
                doOperation(op, numUsers, offset);

                System.out.print("Would you like to perform another operation? [y/n]: ");
                
                cont = scanner.next();

                while (!cont.equalsIgnoreCase("y")  && !cont.equalsIgnoreCase("n")) {
                    System.out.print("Please enter y or n: ");                
                    cont = scanner.next();
                }
            }
            else {
                System.out.println("Unknown operation: "+op);
                usage();
                break;
            }
            
        }

        System.out.println("Goodbye.");

    }

}
