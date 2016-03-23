package org.coniks.coniks_server;
import java.security.interfaces.DSAPublicKey;
import java.util.Arrays;


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