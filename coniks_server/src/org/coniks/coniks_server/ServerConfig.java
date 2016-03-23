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

import java.util.Scanner;
import java.util.ArrayList;
import java.lang.NumberFormatException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;

/** Sets various configuration parameters 
 * for a {@link ConiksServer}.
 *
 *@author Marcela S. Melara (melara@cs.princeton.edu)
 */
public class ServerConfig{

    private final int PORT_IDX = 0;
    private final int NAME_IDX = 1;
    private final int FULL_NAME_IDX = 2;
    private final int MSGHAND_LOG_PATH_IDX = 3;
    private final int TIMER_LOG_PATH_IDX = 4;
    private final int SERVER_LOG_PATH_IDX = 5;
    private final int EPOCH_INTERVAL_IDX = 6;   
    private final int KEYSTORE_PATH_IDX = 7;
    private final int KEYSTORE_PWD_IDX = 8;
    private final int TRUSTSTORE_PATH_IDX = 9;
    private final int TRUSTSTORE_PWD_IDX = 10;

    /** The port number on which the CONIKS server is listening
     */
    public int PORT = -1;

    /** A short name for the server (e.g. an alias used when
     * generating certificates for this server
     */
    public String NAME = "";

    /** The server's full hostname (can also be an IP address)
     */
    public String FULL_NAME = "";

    /** The path to the server's message handler log
     */
    public String MSGHAND_LOG_PATH = "";

    /** The path to the server's epoch timer log
     */
    public String TIMER_LOG_PATH = "";

    /** The path to the server's main log
     */
    public String SERVER_LOG_PATH = "";

    /** The time interval between epochs in
     * milliseconds
     */
    public int EPOCH_INTERVAL = -1;

    /** The path to the server's private key store
     */
    public String KEYSTORE_PATH = "";

    /** The password to the server's private key store
     */
    public String KEYSTORE_PWD = "";
    
    /** The path to the server's trusted certificate store
     */
    public String TRUSTSTORE_PATH = "";
    
    /** The password to the server's trusted certificate store
     */
    public String TRUSTSTORE_PWD = "";

    /** The UNIX epoch time at which this instance of the server
     * was started up. This is used as the starting point for "counting" epochs.
     */
    public long STARTUP_TIME = -1;

    /** Set a {@link ConiksServer}'s configuration according to the following
     * default parameters.
     */
    public ServerConfig(){
        this.PORT = 40012;
        this.NAME = "server";
        this.FULL_NAME = "server.com";
        this.MSGHAND_LOG_PATH = "/path/to/logs/msg-handler-%g";
        this.TIMER_LOG_PATH = "/path/to/logs/epoch-timer-%g";
        this.SERVER_LOG_PATH = "/path/to/logs/server-%g";
        this.EPOCH_INTERVAL = 3600000; // one hour in milliseconds
        this.KEYSTORE_PATH = "/path/to/keystore";
        this.KEYSTORE_PWD = "";
        this.TRUSTSTORE_PATH = "/path/to/truststore";
        this.TRUSTSTORE_PWD = "";
        this.STARTUP_TIME = System.currentTimeMillis();
    }

    /** Set a {@link ConiksServer}'s configuration according to the parameters in
     * {@code configFile}.
     * To avoid problems in case of an Exception, this constructor will first
     * set the configuration to the specified default values from the first constructor.
     */
    public ServerConfig(String configFile) {
        
        // first set default values, then see if we can read from file
        this();

        try {
            Scanner in = new Scanner (new FileInputStream(configFile));

            // read in all configs from the file, assumes they are in the following order
            ArrayList<String> configs = new ArrayList<String>();
            while (in.hasNextLine()) {
                configs.add(in.nextLine());
            }

            in.close();
            
            this.PORT = Integer.parseInt(configs.get(PORT_IDX));
            this.NAME = configs.get(NAME_IDX);
            this.FULL_NAME = configs.get(FULL_NAME_IDX);
            this.MSGHAND_LOG_PATH = configs.get(MSGHAND_LOG_PATH_IDX);
            this.TIMER_LOG_PATH = configs.get(TIMER_LOG_PATH_IDX);
            this.SERVER_LOG_PATH = configs.get(SERVER_LOG_PATH_IDX);
            this.EPOCH_INTERVAL = Integer.parseInt(configs.get(EPOCH_INTERVAL_IDX));
            this.KEYSTORE_PATH = configs.get(KEYSTORE_PATH_IDX);
            this.KEYSTORE_PWD = configs.get(KEYSTORE_PWD_IDX);
            this.TRUSTSTORE_PATH = configs.get(TRUSTSTORE_PATH_IDX);
            this.TRUSTSTORE_PWD = configs.get(TRUSTSTORE_PWD_IDX);
            
            this.STARTUP_TIME = System.currentTimeMillis();
        }
        catch (Exception e) {
            // the config returned may still have some default values!
            System.out.println("Error in ServerConfig: "+e.getMessage());
        }
    }

}
