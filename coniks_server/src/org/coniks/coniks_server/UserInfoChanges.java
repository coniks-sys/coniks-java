package org.coniks.coniks_server;

import java.util.PriorityQueue;


// This class isnt being used anywhere...
// Might use it later though
// TODO

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



