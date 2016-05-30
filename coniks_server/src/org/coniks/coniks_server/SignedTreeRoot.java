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

/** Represents a signed tree root, which is generated
 * at the beginning of every epoch.
 * Signed tree roots contain the current root node,
 * the current and previous epochs, the hash of the 
 * previous STR, and its signature.
 * Signed tree roots
 *
 *@author Marcela S. Melara (melara@cs.princeton.edu)
 */
public class SignedTreeRoot {
    RootNode root;
    long epoch;
    long prevEpoch;
    byte[] prevStrHash;
    byte[] sig;
    SignedTreeRoot prev;

    /** Constructs a signed tree root containing the RootNode
     * {@code r}, the signature {@code sig}, the previous epoch
     * {@code prevEp}, the hash of the previous STR {@code prevHash},
     * the signature {@code sig}, and the previous STR in the chain 
     {@code p} for epoch {@code ep}.
    */
    public SignedTreeRoot(RootNode r, long ep, long prevEp, 
                          byte[] prevHash, byte[] sig, SignedTreeRoot p){
	    this.root = r;
	    this.epoch = ep;
            this.prevEpoch = prevEp;
	    this.prevStrHash = prevHash;
            this.sig = sig;
            this.prev = p;
	}

    /** Gets this signed tree root's root node.
     *
     *@return This signed tree root's {@link RootNode}.
     */
    public RootNode getRoot(){
        return this.root;
    }
    
    /** Gets this signed tree root's epoch.
     *
     *@return This signed tree root's epoch as a {@code long}.
     */
    public long getEpoch(){
        return this.epoch;
    }

    /** Gets this signed tree root's previous epoch.
     *
     *@return This signed tree root's previous epoch as a {@code long}.
     */
    public long getPrevEpoch(){
        return this.prevEpoch;
    }

    /** Gets this signed tree root's previous epoch.
     *
     *@return This signed tree root's previous epoch as a {@code long}.
     */
    public byte[] getPrevSTRHash() {
        return this.prevStrHash;
    }
    
    /** Gets this signed tree root's signature.
     *
     *@return This signed tree root's signature as a {@code byte[]}.
     */
    public byte[] getSignature(){
        return this.sig;
    }
    
    /** Gets the signed tree root preceding this signed tree root.
     *
     *@return This signed tree root's preceding.
     */
    public SignedTreeRoot getPrev(){
        return this.prev;
    }

    // don't want setters because each STR should be final

}
