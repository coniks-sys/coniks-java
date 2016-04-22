public class ServerHistory {

    /** The head of the directory history hash chain 
     * of {@link SignedTreeRoot}s.
     */
    public static SignedTreeRoot curSTR;

    /** The length of the directory history in
     * number of recorded STRs.
     */
    private static long length;

    /** Inserts the signed tree root for the next epoch at the head 
    * of the history hash chain.
    * Ensures that the epochs are monotonically increasing and at least
    * EPOCH_INTERVAL apart.
    *
    *@param newSTR the signed tree root for the next epoch.
    *@return true if the STR is valid, false otherwise
    */
    public static synchronized boolean addNextSTR(SignedTreeRoot newSTR) {
        
        long nextEpoch = curSTR.getEpoch()+ConiksServer.CONFIG.EPOCH_INTERVAL;

        if (newSTR.getEpoch() < nextEpoch) {
            ConiksServer.serverLog.error("Next epoch's STR has bad epoch");
            return false;
        }

        // Do we want to do some signature verification here?

        // reassign pointers
        newSTR.setPrev(curSTR);
        curSTR = newSTR;

        // increment the length of the history hash chain
        length++;
        
        // TODO: evict oldest x STRs once length hits a certain value

        return true;
    }

    /** Retrieves the signed tree root for epoch {@code ep} from the linked
     * list representing the history.
     *
     *@return The signed tree root for epoch {@code ep}.
     *@throws An {@code UnsupportedOperationException} in case the 
     * head of the list is reached before the requested signed tree root is found.
     */
    public static synchronized SignedTreeRoot getSTR(long ep){
        SignedTreeRoot runner = curSTR;
        
        while(runner.getEpoch() > ep && runner != null){                
                // need to check if we reached the head of the list
                if (runner.getPrev() == null) {
                    throw new UnsupportedOperationException("reached the head of the list!");
                }
                else{
                    runner = runner.getPrev();
                }
        }
        
        return runner;
    }



}
