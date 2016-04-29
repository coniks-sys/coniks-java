/*
  Copyright (c) 2016, Princeton University.
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

import com.google.protobuf.*;

import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import javax.crypto.*;

/** Represents a CONIKS user and all associated data
 * 
 *@author Marcela S. Melara (melara@cs.princeton.edu)
 */
public class ConiksUser {

    private String username;
    private boolean allowsUnsignedChanges;

    /** Initializes the user with the username and set the default change policy to
     * strict (i.e. {@code allowsUnsignedChanges} is {@code false}.
     *
     *@param uname this user's username
     */
    public ConiksUser (String uname) {
        username = uname;
        allowsUnsignedChanges = false; // strict default for now
    }
    
    /** Returns this CONIKS user's username
     *
     *@return the CONIKS user's username
     */
    public String getUsername() {
        return username;
    }

     /** Returns this CONIKS user's public key
     *
     *@return the CONIKS user's public key
     */
    public DSAPublicKey getPubKey() {
        return KeyOps.loadDSAPublicKey(username);
    }

    /** Indicates whether this CONIKS user allows unsigned key changes
     *
     *@return true if the user allows unsigned changes, false otherwise.
     */
    public boolean isAllowsUnsignedChanges() {
        return allowsUnsignedChanges;
    }
    
    // no setter for name because we don't want the name to change once
    // the user has been created

     /** Sets this CONIKS user's public key
     *
     *@param pub the public key  the CONIKS user's public key
     *@param keyChangeAuth the signed key change statement; null is accepted if 
     * {@code allowsUnsignedChanges} is set to {@code true}.
     *@return true if the key change authorization passed, or if the user allows unsigned key
     * key changes. False otherwise.
     */
    public boolean setPubKey(DSAPublicKey pub, byte[] keyChangeAuth) {

        // check if we have an auth statement when we need one
        if (keyChangeAuth == null && !allowsUnsignedChanges) {
            ClientLogger.error("Attempt to change keys without authorization");
            return false;
        }

        // TODO acutally check the key change auth
        
        KeyOps.saveDSAPublicKey(username, pub);

        return true;
    }

    /** Sets the unsigned key change flag to true
     */
    public void allowUnsignedChanges() {
        allowsUnsignedChanges = true;
    }

    /** Sets the unsigned key change flag to false
     */
    public void disallowUnsignedChanges() {
        allowsUnsignedChanges = false;
    }

}
