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
    private String keyData; // TODO change this to be bytes
    private DSAPublicKey changePubKey;
    private boolean allowsUnsignedChanges;
    private boolean allowsPublicVisibility;

    /** Initializes the user with the username, public key data, public change key,
     * and sets the default change and visibility policies (i.e. {@code allowsUnsignedChanges} 
     * and {@code allowsPublicVisibility} are both {@code true}.
     *
     *@param uname this user's username
     *@param data this user's key data
     *@param changePubKey this user's change public key
     */
    public ConiksUser (String uname, String data, DSAPublicKey changePk) {
        username = uname;
        keyData = data;
        changePubKey = changePk;
        KeyOps.saveDSAPublicKeyFile(username, changePk);
        allowsUnsignedChanges = true;
        allowsPublicVisibility = true;
    }
    
    /** Returns this CONIKS user's username
     *
     *@return the CONIKS user's username
     */
    public String getUsername() {
        return username;
    }

     /** Returns this CONIKS user's key data
     *
     *@return the CONIKS user's key data
     */
    public String getKeyData() {
        return keyData;
    }

     /** Returns this CONIKS user's data change public key
     *
     *@return the CONIKS user's data public key
     */
    public DSAPublicKey getChangePubKey() {
        return changePubKey;
    }

    /** Indicates whether this CONIKS user allows unsigned key changes
     *
     *@return true if the user allows unsigned changes, false otherwise.
     */
    public boolean isAllowsUnsignedChanges() {
        return allowsUnsignedChanges;
    }

     /** Indicates whether this CONIKS user allows her key to have public visibility
     *
     *@return true if the user allows public visibility, false otherwise.
     */
    public boolean isAllowsPublicVisibility() {
        return allowsPublicVisibility;
    }

    /** Loads the user's key change public key from disk. 
     * This can be used after the user's key has been evicted from memory.
     */
    public void loadChangePubKey() {
        changePubKey = KeyOps.loadDSAPublicKeyFile(username);
    }

    /** Unloads the user's key change public key from memory.
     */
    public void unloadChangePubKey() {
        changePubKey = null;
    }
    
    // no setter for name because we don't want the name to change once
    // the user has been created

    /** Sets the user's key data. Expects that the caller has verified the
     * change operation based on the user's key change policy.
     */
    public void setKeyData(String newData) {
        keyData = newData;
    }
    
    /** Sets the user's change public key and saves the key to disk.
     *
     *@param changePk the DSA public key to set as the user's change key.
     */
    public void setChangePubKey(DSAPublicKey changePk) {
        changePubKey = changePk;
        KeyOps.saveDSAPublicKeyFile(username, changePk);
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

     /** Sets the public visibility flag to true
     */
    public void allowPublicVisibility() {
        allowsPublicVisibility = true;
    }

    /** Sets the public visibility flag to false
     */
    public void disallowPublicVisibility() {
        allowsPublicVisibility = false;
    }

}
