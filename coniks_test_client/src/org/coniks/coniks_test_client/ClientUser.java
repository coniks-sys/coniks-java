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

import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import javax.crypto.*;

/** Represents the user using a CONIKS client. This is an
 * extension of a regular {@link ConiksUser} since the client's
 * user also has an associated username, public key and
 * security policy flags, but also needs access to a corresponding
 * private key used for signing key changes etc.
 * 
 *@author Marcela S. Melara (melara@cs.princeton.edu)
 */
public class ClientUser extends ConiksUser {

    private DSAPrivateKey changePrivKey;
    
    /** Initializes the client's user with the username and 
     * ConiksUser defaults.
     *
     *@param uname this user's username
     */
    public ClientUser (String uname, String data, KeyPair kp) {
        super(uname, data, (DSAPublicKey)kp.getPublic());
        KeyOps.saveDSAPrivateKeyFile(uname, (DSAPrivateKey)kp.getPrivate());
    }

    /** Loads the user's key change private key from disk. The caller should free
     * the key's memory after use.
     */
    public DSAPrivateKey loadChangePrivKey() {
        changePrivKey = KeyOps.loadDSAPrivateKeyFile(username);
        return changePrivKey;
    }

    /** Unloads the user's key change private key from memory.
     */
    public void unloadChangePrivKey() {
        changePrivKey = null;
    }

    /** Saves the new change key pair to disk. This is called every time the client
     * performs some mapping data change and updates the change key.
     *
     *@param kp the new change key pair to save.
     */
    public void saveChangeKeyPair (KeyPair kp) {
        KeyOps.saveDSAPrivateKeyFile(username, (DSAPrivateKey)kp.getPrivate());
        super.setChangePubKey((DSAPublicKey)kp.getPublic());
    }

}
