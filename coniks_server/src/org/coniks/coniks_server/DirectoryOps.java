package org.coniks.coniks_server;

public class DirectoryOps {

    // keeps all the operations pending to be inserted into the directory
    private static PriorityQueue<Triplet<byte[], UserLeafNode, Operation>> pendingQueue;   

    // this is a counter to be used to sort the uln changes so they happen in-order for the same person
    private static long ulnCounter = 0;

    /** Adds a new registration with {@code uname} and {@code pk}
     * to the pending queue.
     */
    public static synchronized void register(String uname, String pk){            
        byte[] index = ServerUtils.unameToIndex(uname);
        UserLeafNode uln = new UserLeafNode(uname, pk, curEpoch+CONFIG.EPOCH_INTERVAL, 0, true, true, null, index);
        pendingQueue.add(Triplet.with(index, uln, (Operation)new Register()));
    }

     /** Adds a new mapping change for {@code uname} with {@code pk}
     * to the pending queue.
     */
    public static synchronized void mappingChange(String uname, String newKey, DSAPublicKey kPrime, 
        boolean allowsUnsignedKC, boolean allowsPublicLookup, 
        byte[] msg, byte[] sig) {
        byte[] index = ServerUtils.unameToIndex(uname);
        UserLeafNode uln = new UserLeafNode(uname, newKey, curEpoch+CONFIG.EPOCH_INTERVAL, 0, true, true, kPrime, index);
        pendingQueue.add(Triplet.with(index, uln, 
            (Operation)new KeyChange(newKey, kPrime, allowsUnsignedKC, allowsPublicLookup, msg, sig, curEpoch, epochCounter++)));
    }

    /** Searches for the username {@code uname} in the key directory.
     *
     *@return the user's entry in the directory or null if the name can't be found.
     */
    public static synchronized UserLeafNode findUser(String uname) {
        RootNode root = ServerHistory.curSTR.getRoot();
        
        return getUlnFromTree(name, root);
    }

    /** Goes through the pending queue and updates the key directory
     * according to the pending operations.
     * This function is called at the end of the new epoch.
     */
    public static synchronized void updateDirectory() {
  
        // this should never be the case
        if(ServerHistory.curSTR == null){
            ConiksServer.serverLog.error("Trying to update a server without a history.");
            return;
        }
        
        RootNode curRoot = ServerHistory.curSTR.getRoot();
        long curEpoch = ServerHistory.curSTR.getEpoch();

        RootNode newRoot = buildNextEpochTree(pendingQueue, curRoot,
                                               curEpoch, ConiksServer.CONFIG.EPOCH_INTERVAL);

	// it's safe to clear the pending queue.
	pendingQueue.clear();
    }

    /** Builds the Merkle prefix tree for the next epoch after 
     * with the pending registrations in {@code pendingQ}, the current epoch's
     * root node {@code curRoot}, the current epoch {@code ep},
     * and the epoch interval {@code epInt}.
     *
     *@return The {@link RootNode} for the next epoch or {@code null} in case of an error.
     */
    private static RootNode buildNextEpochTree(
                                              PriorityQueue<Triplet<byte[], UserLeafNode, Operation>> pendingQ,
					      RootNode curRoot, 
					      long ep, int epInt){

	UserTreeBuilder utb = UserTreeBuilder.getInstance();
	
        // curRoot will become the next epoch's prev so we need to pass current root 
        // hash to buildTree()
        byte[] rootBytes = ServerUtils.convertRootNode(curRoot);
	return utb.copyExtendTree(curRoot, ServerUtils.hash(rootBytes), pendingQ, 
				     ep + epInt);
    }

    // traverses down the tree until we reach the requested user leaf node
    // msm: this pretty much repeats the traversal in ServerOps.generateAuthPathProto
    // so we should really find a way to remove this redundancy
    private synchronized UserLeafNode getUlnFromTree(String username,
                                                     RootNode root) {
        
        // traverse based on lookup index for this name
        byte[] lookupIndex = ServerUtils.unameToIndex(username);
        
        // not worth doing this recursively
        int curOffset = 0;
        TreeNode runner = root;
        
        msgLog.log("searching for: "+ServerUtils.bytesToHex(lookupIndex));
        
        while (!(runner instanceof UserLeafNode)) {
            
            // direction here is going to be false = left,
            //                               true = right
            boolean direction = ServerUtils.getNthBit(lookupIndex, curOffset);
            
            if (runner == null){
                break;
            }
            
            if (runner instanceof RootNode) {
                
                    RootNode curNodeR = (RootNode) runner;
                    
                    if(!direction){
                        runner = curNodeR.getLeft();
                    }
                    else {
                        runner = curNodeR.getRight();
                    }

                }

                else {
                    InteriorNode curNodeI = (InteriorNode) runner;
               
                    if(!direction){
                        runner = curNodeI.getLeft();
                    }                             
                    else {
                        runner = curNodeI.getRight();
                    }

                    // msm: rather be safe than sorry
                    if (runner == null){
                        break;
                    }
                    
                }
               
                curOffset++;
            }

            // if we have found a uln, make sure it doesn't just have a common prefix
            // with the requested node
            if (runner != null && runner instanceof UserLeafNode) {
                // msm: this is ugly
                if (!username.equals(((UserLeafNode)runner).getUsername())) {
                        return null;
                    }
            }

            // we expect the runner to be the right uln at this point
            return (UserLeafNode) runner;
  
        }

}
