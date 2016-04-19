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

import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import javax.crypto.*;
import java.math.BigInteger;
import java.util.Arrays;

/** Implements the operations that interface
 * a CONIKS client with a CONIKS server.
 * 
 *@author Marcela S. Melara (melara@cs.princeton.edu)
 *@author Michael Rochlin
 */
public class ConiksClient {

    // Config settings now set in main in TestClient
    public ClientConfig CONFIG;
    private boolean isFullOp = true;

    private String username;
    private KeyPair keyPair;

    // logs are useful
    public static ClientLogger clientLog = null;

    /** Initializes the client with the username associated to this client */
    public ConiksClient (String uname) {
        username = uname;
        keyPair = null;
    }

    /** Sets the operating mode of the client: either full or testing.
     *
     *@param isFullOp indicates if the client is in full operating mode or not.
     */
    public void setOpMode (boolean isFullOpMode) {
        isFullOp = isFullOpMode;
    }

    /** Sets the default truststore according to the {@link ClientConfig}.
     * This is needed to set up SSL connections with a CONIKS server.
     */
    public void setDefaultTruststore() {
        System.setProperty("javax.net.ssl.trustStore", 
                           CONFIG.TRUSTSTORE_PATH);
        System.setProperty("javax.net.ssl.trustStorePassword",
                           CONFIG.TRUSTSTORE_PWD);
        System.setProperty("javax.net.ssl.keyStore", CONFIG.PRIVATE_KEYSTORE_PATH);
        System.setProperty("javax.net.ssl.keyStorePassword", CONFIG.PRIVATE_KEYSTORE_PWD);
    }

    /** Sets up the logging for the client.
     *
     *@param logPath the path where the logs are to be written
     */
    public static void  setupLogging(String logPath) {
        clientLog = ClientLogger.getInstance(logPath+"/client-%g");
    }

}
