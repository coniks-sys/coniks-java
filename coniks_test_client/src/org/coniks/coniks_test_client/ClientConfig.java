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

/** Sets various configuration parameters 
 * for a {@link ConiksClient}.
 *
 *@author Marcela Melara (melara@cs.princeton.edu)
 *@author Michael Rochlin
 */

package org.coniks.coniks_test_client;

import java.util.Scanner;
import java.util.ArrayList;
import java.io.FileInputStream;

public class ClientConfig{

    private final int PORT_IDX = 0;
    private final int TRUSTSTORE_PATH_IDX = 1;
    private final int TRUSTSTORE_PWD_IDX = 2;
    private final int PRIVATE_KEYSTORE_PATH_IDX = 3;
    private final int PRIVATE_KEYSTORE_PWD_IDX = 4;

    /** The port number on which the CONIKS server is listening
     */
    public int PORT = -1;
    
    /** The path to the client's trusted certificate store
     */
    public String TRUSTSTORE_PATH = "";
    
    /** The password to the client's trusted certificate store
     */
    public String TRUSTSTORE_PWD = "";

    /** The path to the client's private DSA key */
    public String PRIVATE_KEYSTORE_PATH = "";
    public String PRIVATE_KEYSTORE_PWD = "";

    /** Set a {@link ConiksClient}'s configuration according to the following
     * default parameters.
     */
    public ClientConfig(){
        this.PORT = 40012;
        this.TRUSTSTORE_PATH = "";
        this.TRUSTSTORE_PWD = "";
        this.PRIVATE_KEYSTORE_PATH = "";
        this.PRIVATE_KEYSTORE_PWD = "";
    }

    /** Set a {@link ConiksClient}'s configuration according to the parameters in
     * {@code configFile}.
     * To avoid problems in case of an Exception, this constructor will first
     * set the configuration to the specified default values from the first constructor.
     */
    public ClientConfig(String configFile) {

        // this is just in case we fail below
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
            this.TRUSTSTORE_PATH = configs.get(TRUSTSTORE_PATH_IDX);
            this.TRUSTSTORE_PWD = configs.get(TRUSTSTORE_PWD_IDX);
            this.PRIVATE_KEYSTORE_PATH = configs.get(PRIVATE_KEYSTORE_PATH_IDX);
            this.PRIVATE_KEYSTORE_PWD = configs.get(PRIVATE_KEYSTORE_PWD_IDX);
            
        }
        catch (Exception e) {
            // caution the configuration may still have default values at this point
            System.out.println("Error in ClientConfig: "+e.getMessage());
        }
    }

}
