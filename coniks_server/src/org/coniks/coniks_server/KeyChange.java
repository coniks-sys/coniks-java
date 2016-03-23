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

package org.coniks.coniks_server;

import java.security.interfaces.DSAPublicKey;
import java.util.Arrays;

/** Implements a key change operation.
 *
 *@author Michael Rochlin
 */
public class KeyChange extends Operation {
    public String newBlob;
    public DSAPublicKey newChangeKey;
    public boolean allowsUnsignedKeychange;
    public boolean allowsPublicLookup;
    public byte[] sig; 
    public byte[] msg;
    public long ep0;
    public long counter;

    /** A KeyChange object does the actual work of changing the binding 
        It first checks whether the binding change is actually allowed */
    public KeyChange(String newBlob, DSAPublicKey changeKey, 
        boolean allowsUnsignedKeychange, boolean allowsPublicLookup, 
        byte[] msg, byte[] sig, long ep0, long counter) {
        this.newBlob = newBlob;
        this.newChangeKey = changeKey;
        this.allowsUnsignedKeychange = allowsUnsignedKeychange;
        this.allowsPublicLookup = allowsPublicLookup;
        this.msg = msg == null ? null : Arrays.copyOf(msg, msg.length);
        this.sig = sig == null ? null : Arrays.copyOf(sig, sig.length);
        this.ep0 = ep0;
        this.counter = counter;
        ServerLogger.log("Made a KC object with sig = " + Arrays.toString(this.sig));
    }

    /** Tries to verify the keychange
        Returns true if it can, false otherwise */
    public boolean canChangeInfo(UserLeafNode uln) {
        // does all the checking for changing key, but doesnt actually make changes
        if (!uln.allowsUnsignedKeychange() && sig == null) {
            // tried to make an unsigned change
            // error
            ServerLogger.error("Tried to make unsigned KeyChange but wasn't allowed");
            return false;
        }
        if (!uln.allowsUnsignedKeychange() && !SignatureOps.verifySigFromDSA(msg, sig, uln.getChangeKey())) {
            ServerLogger.error("Requires that key changes be signed, but the signature was invalid");
            return false;
        }
        return true;
    }

    /** Checks if the keychange is valid and does it if allowed */
    public boolean changeInfo(UserLeafNode uln) {
        // does the actual key change        
        if (!canChangeInfo(uln)) {
            return false;
        }
        // do the actual key change
        uln.setPublicKey(newBlob);
        uln.setChangeKey(newChangeKey);
        uln.setAllowsUnsignedKeychange(allowsUnsignedKeychange);
        uln.setAllowsPublicLookup(allowsPublicLookup);
        if (sig != null) {
            uln.setSignature(sig);
        }
        else {
            uln.setSignature(null);
        }
        uln.setLastMsg(msg);
        uln.setEpochChanged(ep0);
        return true;
    }

}
