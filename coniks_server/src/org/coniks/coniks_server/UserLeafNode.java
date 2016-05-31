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

import java.io.Serializable;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;

/** Represents a leaf node containing a user's entry in the CONIKS key directory
 *  in the CONIKS binary Merkle prefix tree.
 *
 *@author Marcela S. Melara (melara@cs.princeton.edu)
 *@author Aaron Blankstein
 *@author Michael Rochlin
 */
public class UserLeafNode extends LeafNode implements Serializable {
    
    String username;
    // Note that this is really a blob, but changing it everywhere might introduce 
    // issues for for legacy reasons its still called pubKey
    String pubKey; 
    long epochAdded;
    long epochChanged;
    boolean allowUnsignedKeychange;
    boolean allowPublicLookup;
    byte[] index;
    byte[] signature; // The signature of the last msg
    DSAPublicKey changeKey; // The public DSA key for changing
    byte[] lastMsg; // The last msg

    public UserLeafNode(String u, String blob, long e, int lvl){
        this(u,blob,e,lvl,true,true);
    }
    
    public UserLeafNode(String u, String blob, long e, int lvl, boolean allowUnsignedKeychange, boolean allowPublicLookup) {
        this(u,blob,e,lvl,allowUnsignedKeychange,allowPublicLookup, null);
    }
    public UserLeafNode(String u, String blob, long e, int lvl, byte[] index) {
        this(u,blob,e,lvl,true,true,null,index);
    }
    public UserLeafNode(String u, String blob, long e, int lvl, boolean allowUnsignedKeychange, boolean allowPublicLookup, DSAPublicKey changeKey) {
        this.username = u;
        this.pubKey = blob;
        this.epochAdded = e;
        this.epochChanged = e;
        this.allowUnsignedKeychange = allowUnsignedKeychange; // this is the default for now
        this.allowPublicLookup = allowPublicLookup; // default for now
        this.left = null;
        this.right = null;
        this.parent = null;
        this.level = lvl;
        this.index = null;
        this.signature = new byte[126]; // dummy array
        this.changeKey = changeKey;
    }

    public UserLeafNode(String u, String blob, long e, int lvl, boolean allowUnsignedKeychange, boolean allowPublicLookup, DSAPublicKey changeKey, byte[] index){
        this.username = u;
        this.pubKey = blob;
        this.epochAdded = e;
        this.epochChanged = e;
        this.allowUnsignedKeychange = allowUnsignedKeychange; // this is the default for now
        this.allowPublicLookup = allowPublicLookup; // default for now
        this.left = null;
        this.right = null;
        this.parent = null;
        this.level = lvl;
        this.index = index;
        this.signature = new byte[126]; // dummy array
        this.changeKey = changeKey;
    }
    
    public UserLeafNode(UserLeafNode uln) {
        this.username = uln.username;
        this.pubKey = uln.pubKey;
        this.epochAdded = uln.epochAdded;
        this.epochChanged = uln.epochChanged;
        this.allowUnsignedKeychange = uln.allowUnsignedKeychange;
        this.allowPublicLookup = uln.allowPublicLookup;
        this.left = null;
        this.right = null;
        this.level = uln.level;
        this.index = uln.index;
        this.signature = uln.signature;
        this.changeKey = uln.changeKey;
        this.lastMsg = uln.lastMsg;
    }

     /** Gets the username contained in this UserLeafNode.
     *
     *@return The username as a {@code String}.
     */
    public String getUsername(){
	return this.username;
    }

    /** Gets the public key contained in this UserLeafNode.
     *
     *@return The {@code String} representation of the public key.
     */
    public String getPublicKey(){
        return this.pubKey;
    }

    /** Returns the public key data of this user leaf.
     *<p>
     * Same as {@link UserLeafNode#getPublicKey()}, but using the more generic
     * key data terminology representing that the mapping may also contain other data.
     *@return the public key data mapped in this leaf node
     */
    public String getKeyData() {
        return this.pubKey;
    }
    
    /** Gets the epoch in which this UserLeafNode was added to the tree.
     *
     *@return The epoch as a {@code long}.
     */
    public long getEpochAdded(){
        return this.epochAdded;
    }
    
    /** Checks whether this UserLeafNode allows unsigned key
     * changes.
     *
     *@return {@code true} If it allows unsigned key changes, {@code false}
     * otherwise.
     */
    public boolean allowsUnsignedKeychange(){
        return this.allowUnsignedKeychange;
    }

    /** Checks whether this UserLeafNode allows public lookups.
     *
     *@return {@code true} If it allows public lookups, {@code false}
     * otherwise.
     */
    public boolean allowsPublicLookups() {
        return this.allowPublicLookup;
    }

    /** Gets the last epoch at which this leaf node was changed.
     *
     *@return The epoch as a {@code long}.
     */
    public long getEpochChanged() {
        return this.epochChanged;
    }

    /** Gets the DSA public key used to sign key data changes.
     *
     *@return the DSA public change key.
     */
    public DSAPublicKey getChangeKey() {
        return this.changeKey;
    }

    /** Gets the last key data change message.
     *
     *@return the last key data change message as a {@code byte[]}.
     */
    public byte[] getLastMsg() {
        return this.lastMsg;
    }

    /** Gets the signature on the last key data change message.
     * The caller must verify that this signature is valid for the last message in this leaf node.
     *
     *@return the signature as a {@code byte[]}.
     */
    public byte[] getSignature() {
        return this.signature;
    }

    /** Gets the lookup index for the username in this UserLeafNode.
     *
     *@return The lookup index as a {@code byte[]}.
     */
    public byte[] getIndex() {
        return this.index;
    }
    
    /** Sets the leaf's public key to {@code newKey}.
     */
    public void setPublicKey(String newKey) {
        this.pubKey = newKey;
    }

    /** Sets the key data in this leaf to {@code keyData}.
     *<p>
     * Same as {@link UserLeafNode#setPublicKey(String)}, but using the more generic
     * key data terminology representing that the mapping may also contain other data.
     */
    public void setKeyData(String keyData) {
        this.pubKey = keyData;
    }

    /** Sets the epoch at which the key data in this leaf was changed to {@code ep0}.
     */
    public void setEpochChanged(long ep0) {
        this.epochChanged = ep0;
    }

    /** Sets the unsigned key data change policy flag to {@code b}.
     */
    public void setAllowsUnsignedKeychange(boolean b) {
        this.allowUnsignedKeychange = b;
    }

    /** Sets the public lookup policy flag to {@code b}.
     */
    public void setAllowsPublicLookup(boolean b) {
        this.allowPublicLookup = b;
    }

    /** Sets the DSA public change key to {@code newKey}.
     */
    public void setChangeKey(DSAPublicKey newKey) {
        this.changeKey = newKey;
    }

    /** Sets the last key data change message to {@code msg}.
     */
    public void setLastMsg(byte[] msg) {
        this.lastMsg = msg;
    }
    
    /** Sets the signature on the last key data change message to {@code sig}.
     */
    public void setSignature(byte[] sig) {
        this.signature = sig;
    }   

    /** Sets the lookup index for the username in this UserLeafNode to
     * the {@code byte[]} {@code i}.
     */
    public void setIndex(byte[] i) {
        this.index = i;
    }

    /** Clones (i.e. duplicates) this user leaf node with the
     * given {@code parent} tree node.
     *<p>
     * This function is called as part of the CONIKS Merkle tree
     * rebuilding process at the beginning of every epoch.
     *@return The cloned user leaf node.
     */
    public UserLeafNode clone(TreeNode parent){
	
	UserLeafNode cloneN = new UserLeafNode(this.username, this.pubKey,
                                               this.epochAdded, this.level, this.allowUnsignedKeychange,
                                               this.allowPublicLookup, this.changeKey, this.index);
        cloneN.setSignature(this.signature);
        cloneN.setLastMsg(this.lastMsg);        
	cloneN.parent = parent;
	
	return cloneN;
    }

} // ends UserLeafNode
