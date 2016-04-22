/** Represents a signed tree root, which is generated
 * at the beginning of every epoch.
 * Signed tree roots contain the current root node,
 * the current and previous epochs, the hash of the 
 * previous STR, and its signature.
 * Signed tree roots
 *
 *@author Marcela S. Melara (melara@cs.princeton.edu)
 */
public static class SignedTreeRoot {
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
