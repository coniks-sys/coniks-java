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

import org.coniks.coniks_common.UtilProtos.Commitment;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.DSAParams;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Comparator;

import org.javatuples.Pair;
import org.javatuples.Triplet;

/** Implements various utility functions
 * used by various components of a CONIKS
 * server.
 *
 *@author Marcela S. Melara (melara@cs.princeton.edu)
 *@author Aaron Blankstein
 *@author Michael Rochlin
 */
public class ServerUtils{

    /** The size of the Merkle tree hashes in bits.
     * Current hashing algorithm: SHA-256
     *
     *@deprecated Moved to {@link org.coniks.crypto.Util}.
     */
    @Deprecated
    public static final int HASH_SIZE_BITS =  256;

    /** The size of the Merkle tree hashes in bytes.
     * Current hashing algorithm: SHA-256
     *
     *@deprecated Moved to {@link org.coniks.crypto.Util}.
     */
    @Deprecated
    public static final int HASH_SIZE_BYTES = HASH_SIZE_BITS/8;

    /** The size of the CONIKS server's STR signatures in bytes.
     * Server signature scheme: RSAwithSHA256.
     *
     *@deprecated Moved to {@link org.coniks.crypto.Signing}.
     */
    @Deprecated
    public static final int SIG_SIZE_BYTES = 256;

    /** The maximum number of bytes logged per log file.
     *
     *@deprecated Moved to {@link org.coniks.util.Convert}.
     */
    @Deprecated
    public static final int MAX_BYTES_LOGGED_PER_FILE = (1 << 15);

    /** The maximum number of log files per log.
     *
     *@deprecated Moved to {@link org.coniks.util.Convert}.
     */
    @Deprecated
    public static final int MAX_NUM_LOG_FILES = 5;

    @Deprecated
    private static final char[] hexArray = "0123456789ABCDEF".toCharArray();

    /** Prints server status and error messages.
     * Used primarily for testing mode.
     *
     *@param isErr indicates whether this is an error message
     *@param msg the status message to print
     *
     *@deprecated Replaced with private method in
     * {@link org.coniks.coniks_server.ConiksServer}.
     */
    @Deprecated
    public static void printStatusMsg (boolean isErr, String msg) {
        String status = msg;
        if (isErr) {
            status = "Error: "+status;
        }

        System.out.println(status);
    }

    /** Generates the cryptographic hash of {@code input}.
     * Current hashing algorithm: SHA-256.
     *
     *@return The hash as a {@code byte[]} or null in case of an error.
     *@deprecated Replaced with {@link org.coniks.crypto.Util#digest(byte[])}
     */
    @Deprecated
    public static byte[] hash(byte[] input){

        try{
            MessageDigest md = MessageDigest.getInstance("SHA-256");

            byte[] digest = md.digest(input);

            return digest;

        }
        catch(NoSuchAlgorithmException e){
            ServerLogger.error("SHA-256 is not a valid algorithm for some reason");
        }

        return null; // should never get here
    }

    /** Generates the cryptographic hash of the {@code left}
     * and {@code right} subtree hashes of a Merkle tree node.
     * This is really just a wrapper around {@link ServerUtils#hash(byte[])}.
     *
     *@return The hash as a {@code byte[]} or null in case of an error.
     */
    public static byte[] hashChildren(byte[] left, byte[] right){

        byte[] childrenBytes = new byte[left.length+right.length];

        ByteBuffer arr = ByteBuffer.wrap(childrenBytes);
        arr.put(left);
        arr.put(right);

        byte[] children = arr.array();

        try{
            MessageDigest md = MessageDigest.getInstance("SHA-256");

            byte[] digest = md.digest(children);

            return digest;

        }
        catch(NoSuchAlgorithmException e){
            TimerLogger.error("SHA-256 is not a valid algorithm for some reason");
        }

        return null; // should never get here

    }

    // from Stackoverflow 9655181
     /** Converts a {@code byte[]} into a String
     * of its hexadecimal representation.
     *
     *@return The hex representation of {@code bytes} as a String.
     *@deprecated Moved to {@link org.coniks.util.Convert}.
     */
    @Deprecated
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    /** Converts a UTF-8 String {@code str} to an array of bytes.
     *
     *@deprecated Moved to {@link org.coniks.util.Convert}.
     */
    @Deprecated
    public static byte[] strToBytes (String str) {
        return str.getBytes(Charset.forName("UTF-8"));
    }

    /** Converts a {@code username} to a CONIKS lookup
     * index using a verifiable unpredicctable function (VUF).
     * Current VUF algorithm: SHA-256.
     *
     *@return The {@code byte[]} representation of the
     * lookup index.
     */
    public static byte[] unameToIndex (String uname){
        byte[] b = strToBytes(uname);
        return ServerUtils.hash(b);
    }

     /** Converts a long {@code val} into an array of bytes.
     *
     *@return The {@code byte[]} representation of the long value.
     *@deprecated Moved to {@link org.coniks.util.Convert}.
     */
    @Deprecated
    public static byte[] longToBytes(long val) {
        byte[] byteArr = new byte[8];

        for(int i = 0; i < 8; i++) {
            byte nextByte = (byte)((val >> i*8) & 0xff);
            byteArr[i] = nextByte;
        }

        return byteArr;
    }

    /** Finds the byte in the byte array {@code arr}
     * at offset {@code offset}, and determines whether it is 1 or 0.
     *
     *@return true if the nth bit is 1, false otherwise.
     *@deprecated Moved to {@link org.coniks.util.Convert}.
     */
    @Deprecated
    public static boolean getNthBit(byte[] arr, int offset){
        int arrayOffset = offset / 8;
        int bitOfByte = offset % 8;
        int maskedBit = arr[arrayOffset] & (1 << (7 - bitOfByte));
        return (maskedBit != 0);
    }

    /** Gets the 16-bit prefix of a byte array {@code arr}.
     *
     *@return the first 16 bits of {@code arr} or all zeros if the length
     * of the array is less than 2 bytes.
     *@deprecated Moved to {@link org.coniks.util.Convert}.
     */
    @Deprecated
    public static byte[] getPrefixBytes(byte[] arr){
        byte[] out = new byte[2];

        if (arr.length < 2) {
            out[0] = 0;
            out[1] = 0;
        }
        else {
            out[0] = arr[0];
            out[1] = arr[1];
        }
        return out;
    }

    /** Compares two byte buffers for byte-by-byte equality.
     *
     *@return true if the buffers are identical, false otherwise.
     *@deprecated Use {@link java.util.Arrays#equals(byte[], byte[])}
     */
    @Deprecated
    public static boolean compareByteBuffers(byte[] buf1, byte[] buf2){
        if (buf1.length != buf2.length) {
            return false;
        }

        for(int i = 0; i < buf1.length; i++){
            if(buf1[i] != buf2[i]){
                return false;
            }
        }
        return true;
    }


    /** Converts an RSAPublicKey {@code pub} to a hashable array of bytes.
     * This function is currently unused.
     *
     *@return The {@code byte[]} containing the serialized RSAPublicKey.
     */
    public static byte[] convertRSAPubKey(RSAPublicKey pub){
        byte[] exp = pub.getPublicExponent().toByteArray();
        byte[] mod = pub.getModulus().toByteArray();

        byte[] pubKey = new byte[exp.length+mod.length];

        ByteBuffer arr = ByteBuffer.wrap(pubKey);
        arr.put(exp);
        arr.put(mod);

        return arr.array();
    }

    /** Converts an DSAPublicKey {@code pub} to a hashable array of bytes.
     * This function is currently unused.
     *
     *@return The {@code byte[]} containing the serialized DSAPublicKey.
     */
    public static byte[] convertDSAPubKey(DSAPublicKey pub){
        byte[] g = pub.getParams().getG().toByteArray();
        byte[] p = pub.getParams().getP().toByteArray();
        byte[] q = pub.getParams().getQ().toByteArray();
        byte[] y = pub.getY().toByteArray();

        byte[] pubKey = new byte[g.length+p.length+q.length+y.length];

        ByteBuffer arr = ByteBuffer.wrap(pubKey);
        arr.put(g);
        arr.put(p);
        arr.put(q);
        arr.put(y);

        return arr.array();
    }

    // TODO: use real dsa keys
    /** Converts a {@link UserLeafNode} {@code uln} to a hashable array of bytes.
     *
     *@return The {@code byte[]} containing the serialized UserLeafNode.
     */
    public static byte[] getUserLeafNodeBytes(UserLeafNode uln){
        byte[] pubKey = strToBytes(uln.getPublicKey());
        byte[] usr = strToBytes(uln.getUsername());
        byte[] ck = convertDSAPubKey(uln.getChangeKey());
        byte[] ep_add = longToBytes(uln.getEpochAdded());
        byte[] auk = new byte[]{(byte)(uln.allowsUnsignedKeychange() ? 0x01 : 0x00)};
        byte[] apl = new byte[]{(byte)(uln.allowsPublicLookups() ? 0x01 : 0x00)};

        byte[] leafBytes = new byte[pubKey.length+usr.length+ck.length+ep_add.length+auk.length+
                                    apl.length];

        ByteBuffer arr = ByteBuffer.wrap(leafBytes);
        arr.put(usr);
        arr.put(pubKey);
        arr.put(ck);
        arr.put(ep_add);
        arr.put(auk);
        arr.put(apl);

        return arr.array();
    }

     /** Converts a {@link InteriorNode} {@code in} to a hashable array of bytes.
     *
     *@return The {@code byte[]} containing the serialized InteriorNode.
     */
    public static byte[] getInteriorNodeBytes(InteriorNode in){
        byte[] left = in.getLeftHash();
        byte[] right = in.getRightHash();

        byte[] nodeBytes = new byte[left.length+right.length];

        ByteBuffer arr = ByteBuffer.wrap(nodeBytes);
        arr.put(left);
        arr.put(right);

        return arr.array();
    }

     /** Converts a {@link RootNode} {@code rn} to a hashable array of bytes.
     *
     *@return The {@code byte[]} containing the serialized RootNode.
     */
    public static byte[] getRootNodeBytes(RootNode rn){
        byte[] left = rn.getLeftHash();
        byte[] right = rn.getRightHash();

        byte[] rootBytes = new byte[left.length+right.length];

        ByteBuffer arr = ByteBuffer.wrap(rootBytes);
        arr.put(left);
        arr.put(right);

        return arr.array();
    }

    /** Takes the components of a signed tree root: root node, current epoch,
     * previous epoch, hash of previous STR, and serializes them into
     * a byte[] that can be used to generate the STR's digital signature.
     *
     *@return The {@code byte[]} containing the serialized STR components.
     */
    public static byte[] getSTRBytesForSig(RootNode rn, long ep, long prevEp,
                                                byte[] prevStrHash) {

        byte[] rootBytes = getRootNodeBytes(rn);

        if (rootBytes == null) {
            ServerLogger.error("getSTRBytesForSig: Oops, couldn't get the root node bytes");
            return null;
        }

        byte[] epBytes = longToBytes(ep);
        byte[] prevEpBytes = longToBytes(prevEp);

        byte[] strBytes = new byte[rootBytes.length+epBytes.length+prevEpBytes.length+
                                   prevStrHash.length];

        ByteBuffer arr = ByteBuffer.wrap(strBytes);
        arr.put(rootBytes);
        arr.put(epBytes);
        arr.put(prevEpBytes);
        arr.put(prevStrHash);

        return arr.array();

    }

    /** Converts a {@link SignedTreeRoot} {@code str} to a hashable array of bytes
     *
     *@return The {@code byte[]} containing the serialized STR components.
     */
    public static byte[] getSTRBytes(SignedTreeRoot str) {

        byte[] rootBytes = getRootNodeBytes(str.getRoot());

        if (rootBytes == null) {
            ServerLogger.error("getSTRBytes: Oops, couldn't get the root node bytes");
            return null;
        }

        byte[] epBytes = longToBytes(str.getEpoch());
        byte[] prevEpBytes = longToBytes(str.getPrevEpoch());
        byte[] prevStrHash = str.getPrevSTRHash();
        byte[] sig = str.getSignature();

        byte[] strBytes = new byte[rootBytes.length+epBytes.length+prevEpBytes.length+
                                   prevStrHash.length+sig.length];

        ByteBuffer arr = ByteBuffer.wrap(strBytes);
        arr.put(rootBytes);
        arr.put(epBytes);
        arr.put(prevEpBytes);
        arr.put(prevStrHash);
        arr.put(sig);

        return arr.array();

    }

    /** Comparator for ordering the pendingQueue in
     * increasing order of a data binding lookup index's
     * first 24 bits.
     *
     *@author Marcela S. Melara (melara@cs.princeton.edu)
     *@author Michael Rochlin
     */
    public static class PrefixComparator implements Comparator<Triplet<byte[], UserLeafNode, Operation>> {

        /** Compares the first 24 bits of two data binding lookup indeces.
         *
         *@return 0 if they are equal, 1 if the lookup index of {@code p1} is greater, and
         * -1 if the lookup index of {@code p2} is greater.
         *@throws A RuntimeException if either of the {@code byte[]} of the lookup indeces
         *is smaller than 3 bytes.
         */
        @Override
        public int compare(Triplet<byte[], UserLeafNode, Operation> p1,  Triplet<byte[], UserLeafNode, Operation> p2) {
            byte[] buf1 = p1.getValue0();
            byte[] buf2 = p2.getValue0();

            if (buf1.length < 3 || buf2.length < 3) {
                throw new RuntimeException("bad byte array length");
            }

            for(int i = 0; i < 3; i++){
                if(buf1[i] > buf2[i]){
                    return 1;
                }else if (buf1[i] < buf2[i]){
                    return -1;
                }
            }

            // registrations must always happen before ulnChanges
            // earlier ulnChanges must always happen before later ones
            Operation op1 = p1.getValue2();
            Operation op2 = p2.getValue2();
            if (op1 instanceof Register) {
                return 1;
            }
            if (op2 instanceof Register) {
                return -1;
            }
            if (op1 instanceof KeyChange && op2 instanceof KeyChange) {
                return (((KeyChange)op1).getCounter() > ((KeyChange)op2).getCounter()) ? 1 : -1;
            }

            return 0;
        }
    }

} //ends ServerUtils class
