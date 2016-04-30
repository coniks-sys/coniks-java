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

/** Represents a CONIKS user and all associated data
 * 
 *@author Marcela S. Melara (melara@cs.princeton.edu)
 */
public class ConiksUser {

    protected String username;
    private boolean allowsUnsignedChanges;
    private DSAPublicKey pubKey;

    /** Initializes the user with the username and public key,
     * and sets the default change policy (i.e. {@code allowsUnsignedChanges} 
     * is {@code true}.
     *
     *@param uname this user's username
     */
    public ConiksUser (String uname, DSAPublicKey pub) {
        username = uname;
        pubKey = pub;
        KeyOps.saveDSAPublicKey(username, pub);
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
        return pubKey;
    }

    /** Indicates whether this CONIKS user allows unsigned key changes
     *
     *@return true if the user allows unsigned changes, false otherwise.
     */
    public boolean isAllowsUnsignedChanges() {
        return allowsUnsignedChanges;
    }

    /** Loads the user's key from disk. This can be used after the
     * user's key has been evicted from memory.
     */
    public void loadPubKey() {
        pubKey = KeyOps.loadDSAPublicKey(username);
    }

    /** Unloads the user's public key from memory.
     */
    public void unloadPubKey() {
        pubKey = null;
    }
    
    // no setter for name because we don't want the name to change once
    // the user has been created

    /** Change this CONIKS user's public key.
     *
     *@param pub the public key  the CONIKS user's public key
     *@param keyChangeAuth the signed key change statement; null is accepted if 
     * {@code allowsUnsignedChanges} is set to {@code true}.
     *@return true if the key change authorization passed, or if the user allows unsigned key
     * key changes. False otherwise.
     */
    public boolean changePubKey(DSAPublicKey pub, byte[] keyChangeAuth) {

        // check if we have an auth statement when we need one
        if (keyChangeAuth == null && !allowsUnsignedChanges) {
            ClientLogger.error("Attempt to change keys without authorization");
            return false;
        }
        
        return KeyOps.saveDSAPublicKey(username, pub);

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
