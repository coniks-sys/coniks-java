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

/** Implementation of a simple CONIKS test client
 * that simply displays how each component of the
 * protocol works.
 * The client is completely agnostic to the underlying format
 * of the messages sent to the server (it only needs to know 
 * whether it's using protobufs (TODO: or json)).
 * 
 *@author Marcela S. Melara (melara@cs.princeton.edu)
 */
public class TestClient {

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

    /** Perfoms the CONIKS registration protocol with {@code server}
     * for the dummy user {@code username}.
     *
     *@return Whether the registration succeeded.
     */
    public static boolean register (String username, String server) {
        String pk = createPkFor(username);
        
        ConiksClient.sendRegistrationProto(username, pk, server);
        
        if (ConiksClient.receiveRegistrationRespProto() == null) {
            return false;
        }
        
        return true;
    }

    /** Perfoms the CONIKS public key lookup protocol with {@code server}
     * for the dummy user {@code username}.
     *
     *@return Whether the lookup succeeded.
     */
    // TODO: eventually, I'm going to want to remove this function
    public static boolean keyLookup (String username, String server) {
        long epoch = System.currentTimeMillis();

        ConiksClient.sendKeyLookupProto(username, epoch, server);
        
        if (ConiksClient.receiveAuthPathProto() == null) {
            return false;
        }
        
        return true;
    }

    /** Perfoms the data binding consistency check to
     * verify a dummy user {@code username}'s public key after 
     * lookup at {@code server}.
     *
     *@return Whether the verification succeeded.
     */
    public static boolean doLookupVerification (String username, String server) {
        long epoch = System.currentTimeMillis();

        ConiksClient.sendKeyLookupProto(username, epoch, server);
        
        int result = ConsistencyChecks.verifyDataBindingProto(
                                                              ConiksClient.receiveAuthPathProto(), null);

        if (result == ConsistencyErr.NO_ERR) {
            return true;
        }
        
        return false;
    }

    /** Prints the usage of the TestClient.
     */
    private static void usage() {
        System.out.println("TestClient <server> <command> [iterations = 1] [offset = 0] [verbosity = 0]");
        System.out.println("command := (REGISTER LOOKUP VERIFY)");
    }

    /** Usage:
     * {@code TestClient [-h] <server> <command> [iterations = 1] [offset = 0] [verbosity = 1]}
     * <p>
     * command := ({@code REGISTER LOOKUP VERIFY})
     */
    public static void main(String[] args){
        if (args.length < 2 || args[0].equals("-h")){
            usage();
            return;
        }
        String server = args[0];
        String command = args[1];
        int iters = 1;
        int verbosity = 0;
        int offset = 0;
        try {
            if (args.length >= 3)
                iters = Integer.parseInt(args[2]);
            if (args.length >= 4)
                offset = Integer.parseInt(args[3]);
            if (args.length >= 5)
                verbosity = Integer.parseInt(args[4]);
        }
        catch (NumberFormatException e) {
            System.out.println("iterations, offset and verbosity must be positive integers.");
            return;
        }

        // this is needed to enable the client to communicate using SSL
        ConiksClient.setDefaultTruststore();

        for (int i = 0; i < iters; i++){
            if (i % (1 + (iters / 10)) == 0)
                System.err.print(".");

            String uname = "test-"+(offset+i);
            
            if(command.equalsIgnoreCase("LOOKUP")){

                if (!keyLookup(uname, server))
                    System.out.println ("An error occurred.");
                
            }
            else if (command.equalsIgnoreCase("REGISTER")){

                if (!register(uname, server))
                    System.out.println ("An error occurred.");

            }
            else if (command.equalsIgnoreCase("VERIFY")){

                if (verbosity == 1) {
                    System.out.println("checking: "+uname);
                }
                
                if (!doLookupVerification(uname, server)) 
                    System.out.println("An error occurred.");

            }
            else {
                System.out.println("Unknown command: "+command);
                usage();
                break;
            }
            
        }
        System.out.println(" done!");
    }


}
