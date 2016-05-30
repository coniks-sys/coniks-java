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

import java.security.interfaces.DSAPublicKey;
import java.util.Arrays;

/** Implements a key change operation.
 *
 *@author Michael Rochlin
 */
public class KeyChange extends Operation {
    private String newKeyData;
    private DSAPublicKey newChangeKey;
    private boolean allowsUnsignedChanges;
    private boolean allowsPublicVisibility;
    private byte[] sig; 
    private byte[] msg;
    private long counter;

    /** A KeyChange object does the actual work of changing the 
     * name-to-key mapping.
     *
     *@param newKeyData the new key data for the mapping 
     *@param changeKey the new change key for the mapping
     *@param allowsUnsignedChanges whether the user allows unsigned mapping changes
     *@param allowsPublicVisibility whether the user allows her maping to be publicly visible
     *@param msg the mapping change message
     *@param sig the digital signature on the mapping change message
     *@param epoch the epoch during which the mapping was last changed
     *@param counter the change count for the given epoch (used to order the changes) 
     */
    public KeyChange(String newKeyData, DSAPublicKey changeKey, 
        boolean allowsUnsignedChanges, boolean allowsPublicVisibility, 
        byte[] msg, byte[] sig, long epoch, long counter) {
        this.newKeyData = newKeyData;
        this.newChangeKey = changeKey;
        this.allowsUnsignedChanges = allowsUnsignedChanges;
        this.allowsPublicVisibility = allowsPublicVisibility;
        this.msg = msg == null ? null : Arrays.copyOf(msg, msg.length);
        this.sig = sig == null ? null : Arrays.copyOf(sig, sig.length);
        this.epoch = epoch;
        this.counter = counter;
        ServerLogger.log("Made a KC object with sig = " + Arrays.toString(this.sig));
    }

    /** Gets the change counter for this KeyChange operation.
     *
     *@return the counter as a {@code long}.
     */
    public long getCounter() {
        return this.counter;
    }

    /** Verifies whether the the mapping change is possible given the user's 
     * mapping change policy.
     *
     *@param uln the key directory entry for which to make the check.
     *@return {@code true} if it the mapping can be changed, {@code false} otherwise 
     */
    public boolean canChangeInfo(UserLeafNode uln) {
        // does all the checking for changing key, but doesnt actually make changes
        if (!uln.allowsUnsignedKeychange() && sig == null) {
            // tried to make an unsigned change
            // error
            ServerLogger.error("Tried to make unsigned KeyChange but wasn't allowed");
            return false;
        }
        if (!uln.allowsUnsignedKeychange()
            && !SignatureOps.verifySigFromDSA(msg, sig, uln.getChangeKey())) {
            ServerLogger.error("Requires that key changes be signed, but the signature was invalid");
            return false;
        }
        return true;
    }

    /** Changes a mapping if the user's allows it.
     *
     *@param uln the key directory entry to change
     *@return {@code true} if the change succeeded, {@code false} otherwise.
     */
    public boolean changeInfo(UserLeafNode uln) {
        // does the actual key change        
        if (!canChangeInfo(uln)) {
            return false;
        }
        // do the actual key change
        uln.setPublicKey(newKeyData);
        uln.setChangeKey(newChangeKey);
        uln.setAllowsUnsignedKeychange(allowsUnsignedChanges);
        uln.setAllowsPublicLookup(allowsPublicVisibility);
        if (sig != null) {
            uln.setSignature(sig);
        }
        else {
            uln.setSignature(null);
        }
        uln.setLastMsg(msg);
        uln.setEpochChanged(epoch);
        return true;
    }

}
