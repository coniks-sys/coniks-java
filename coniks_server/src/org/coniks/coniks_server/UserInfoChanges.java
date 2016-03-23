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

import java.util.PriorityQueue;


// This class isnt being used anywhere...
// Might use it later though
// TODO

/**
 *@author Michael Rochlin
 */
public class UserInfoChanges {
    
    /** 
      * Changes the key of uln. Doesn't do any checking in this version  
      */
    public static boolean changeKey(UserLeafNode uln, String newKey) {
        uln.setPublicKey(newKey);
        return true;
    }

    /** Change the key of uln but first check that H(k') matches also update H(k') and sign the keychange */
    public static boolean changeKey(UserLeafNode uln, String newKey, String oldK, byte[] newHashK, byte[] sig) {
        byte[] hk = uln.getHashK();
        if (!uln.allowsUnsignedKeyChange()) {
            byte[] hOldK = ServerUtils.hash(oldK);
            if (ServerUtils.compareByteBuffers(hk, hOldK)) {
                if changeKey(uln, newKey, sig) {
                    self.setHashK(newHashK);
                    return true;
                }
            }        
        }
        return false;
    }

    /** change the key and sign it */
    public static boolean changeKey(UserLeafNode uln, String newKey, byte[] sig) {
        return true;
    }

    public void makeChanges(PriorityQueue<Triplet<byte[], UserLeafNode, Operation>> pq) {
        
    }
}



