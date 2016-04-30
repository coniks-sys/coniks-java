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

import java.util.Scanner;
import java.util.ArrayList;
import java.lang.NumberFormatException;
import java.io.File;
import java.io.FileInputStream;

/** Sets various configuration parameters 
 * for a {@link ConiksServer}.
 *
 *@author Marcela S. Melara (melara@cs.princeton.edu)
 */
public class ServerConfig{

    private static final int PORT_IDX = 0;
    private static final int NAME_IDX = 1;
    private static final int FULL_NAME_IDX = 2;
    private static final int EPOCH_INTERVAL_IDX = 3;   
    private static final int KEYSTORE_PATH_IDX = 4;
    private static final int KEYSTORE_PWD_IDX = 5;
    private static final int TRUSTSTORE_PATH_IDX = 6;
    private static final int TRUSTSTORE_PWD_IDX = 7;

    /** The port number on which the CONIKS server is listening
     */
    public static int PORT = -1;

    /** A short name for the server (e.g. an alias used when
     * generating certificates for this server
     */
    public static String NAME = "";

    /** The server's full hostname (can also be an IP address)
     */
    public static String FULL_NAME = "";

    /** The time interval between epochs in milliseconds
     */
    public static int EPOCH_INTERVAL = -1;

    /** The path to the server's private key store
     */
    public static String KEYSTORE_PATH = "";

    /** The password to the server's private key store
     */
    public static String KEYSTORE_PWD = "";
    
    /** The path to the server's trusted certificate store
     */
    public static String TRUSTSTORE_PATH = "";
    
    /** The password to the server's trusted certificate store
     */
    public static String TRUSTSTORE_PWD = "";

    /** The UNIX epoch time at which this instance of the server
     * was started up. This is used as the starting point for "counting" epochs.
     */
    public static long STARTUP_TIME = -1;

    /** Set a {@link ConiksServer}'s configuration according to the parameters in
     * {@code configFile}.
     *
     * The main server has already checked that {@code configFile} exists, but the
     * parameters in the File may still be malformed. If the server is being tested, 
     * this will skip the keystore and truststore parameters.
     *
     *@param configFile the server configuration file
     *@param isFullOp indicates whether the server is being run in full operation mode or testing mode
     *
     *@return {@code true} if the config file can be read in successfully, {@code false}
     * if an exception occurs, which will cause the server to halt.
     */
    public static boolean readServerConfig(File configFile, boolean isFullOp) {

        try {
            Scanner in = new Scanner (new FileInputStream(configFile));

            // read in all configs from the file, assumes they are in the following order
            ArrayList<String> configs = new ArrayList<String>();
            while (in.hasNextLine()) {
                configs.add(in.nextLine());
            }

            in.close();
            
            PORT = Integer.parseInt(configs.get(PORT_IDX));
            NAME = configs.get(NAME_IDX);
            FULL_NAME = configs.get(FULL_NAME_IDX);
            EPOCH_INTERVAL = Integer.parseInt(configs.get(EPOCH_INTERVAL_IDX));
            KEYSTORE_PATH = configs.get(KEYSTORE_PATH_IDX);
            KEYSTORE_PWD = configs.get(KEYSTORE_PWD_IDX);

            // skip these if we're testing the server
            if (isFullOp) {
                TRUSTSTORE_PATH = configs.get(TRUSTSTORE_PATH_IDX);
                TRUSTSTORE_PWD = configs.get(TRUSTSTORE_PWD_IDX);
            }
            
            // this is always going to be set to the current time
            STARTUP_TIME = System.currentTimeMillis();

            return true;
        }
        catch (Exception e) {
            ConiksServer.serverLog.error("ServerConfig: "+e.getMessage());
        }

        return false;
    }

}
