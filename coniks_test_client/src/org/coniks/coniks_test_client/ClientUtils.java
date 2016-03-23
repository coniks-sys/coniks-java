/*
  Copyright (c) 2015, Princeton University.
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

package org.coniks.coniks_test_client;

import org.coniks.coniks_common.C2SProtos.AuthPath;
import org.coniks.coniks_common.C2SProtos.*;

import org.coniks.coniks_common.UtilProtos.Commitment;
import org.coniks.coniks_common.UtilProtos.Hash;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.Charset;
import java.util.ArrayList;

import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.DSAParams;
import java.math.BigInteger;

/** Implements various utility functions
 * used by various components of a CONIKS
 * client.
 *
 *@author Marcela S. Melara (melara@cs.princeton.edu)
 *@author Michael Rochlin
 */
public class ClientUtils{

    /** The size of the Merkle tree hashes in bits.
     * Current hashing algorithm: SHA-256
     */
    public static final int HASH_SIZE_BITS =  256; 

    /** The size of the Merkle tree hashes in bytes.
     * Current hashing algorithm: SHA-256
     */
    public static final int HASH_SIZE_BYTES = HASH_SIZE_BITS/8;
    
    /** The size of the CONIKS server's STR signatures in bytes.
     * Expected server signature scheme: RSAwithSHA256.
     */
    public static final int SIG_SIZE_BYTES = 256;

    private static final char[] hexArray = "0123456789ABCDEF".toCharArray();

    /** Generates the cryptographic hash of {@code input}.
     * Current hashing algorithm: SHA-256.
     *
     *@return The hash as a {@code byte[]} or null in case of an error.
     */
    public static byte[] hash(byte[] input){

	try{
	    MessageDigest md = MessageDigest.getInstance("SHA-256");
	   
	    byte[] digest = md.digest(input);

	    return digest;

	}
	catch(NoSuchAlgorithmException e){
	    System.out.println("SHA-256 is not a valid algorithm for some reason");
	}

	return null; // should never get here
    }

    /** Generates the cryptographic hash of the {@code left} 
     * and {@code right} subtree hashes of a Merkle tree node.
     * This is really just a wrapper around {@link ClientUtils#hash(byte[])}.
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
	    System.out.println("SHA-256 is not a valid algorithm for some reason");
	}

	return null; // should never get here

    }

    /** Converts a {@code byte[]} into a String
     * of its hexadecimal representation.
     *
     *@return The hex representation of {@code bytes} as a String.
     */
    // from Stackoverflow 9655181
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    /** Converts a {@code byte[]} into a list of integers.
     * This utility is needed for building protobuf messages that
     * contain fields representing byte buffers.
     *
     *@return The {@code arr} as an {@link java.util.ArrayList} of
     * integers.
     */
    public static ArrayList<Integer> byteArrToIntList(byte[] arr){
        ArrayList<Integer> list = new ArrayList<Integer>();
       
        for(int i = 0; i < arr.length; i++){
            int nextInt = arr[i] & 0xff; 
            list.add(new Integer(nextInt));
        }
        
        return list;
    }

     /** Converts a list of integers into a {@code byte[]}.
     * This utility is needed for parsing protobuf messages that
     * contain fields representing byte buffers.
     *
     *@return The {@link java.util.ArrayList} of integers as a {@code byte[]}.
     */
    public static byte[] intListToByteArr(ArrayList<Integer> list){
        byte[] arr = new byte[list.size()];
       
        for(int i = 0; i < list.size(); i++){
            byte nextByte = list.get(i).byteValue();
            arr[i] = nextByte;
        }
        
        return arr;
    }

    /** Converts a UTF-8 String {@code str} to an array of bytes.
     */
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
    public static byte[] unameToIndex (String username){
	byte[] b = strToBytes(username);
	return ClientUtils.hash(b);
    }

    /** Converts a long {@code val} into an array of bytes.
     *
     *@return The {@code byte[]} representation of the long value.
     */
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
     */
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
     */
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
     */
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

    /** Converts the DSAPublicKey {@code pub} to a byte array in g-p-q-y order */
    public static byte[] convertDSAPubKey(DSAPublicKey pub){
        byte[] g = strToBytes(pub.getParams().getG().toString());
        byte[] p = strToBytes(pub.getParams().getP().toString());
        byte[] q = strToBytes(pub.getParams().getQ().toString());
        byte[] y = strToBytes(pub.getY().toString());

        byte[] pubKey = new byte[g.length+p.length+q.length+y.length];

        ByteBuffer arr = ByteBuffer.wrap(pubKey);
        arr.put(g);
        arr.put(p);
        arr.put(q);
        arr.put(y);

        return arr.array();
    }

    /** Converts the DSAPublicKeyProto {@code pub} to a byte array in g-p-q-y order */
    public static byte[] convertDSAPubKey(DSAPublicKeyProto pub){
        byte[] g = strToBytes(pub.getG());
        byte[] p = strToBytes(pub.getP());
        byte[] q = strToBytes(pub.getQ());
        byte[] y = strToBytes(pub.getY());

        byte[] pubKey = new byte[g.length+p.length+q.length+y.length];

        ByteBuffer arr = ByteBuffer.wrap(pubKey);
        arr.put(g);
        arr.put(p);
        arr.put(q);
        arr.put(y);

        return arr.array();
    }

    /** Builds a DSAPublicKeyProto protobuf from the DSA public key {@code pub} */
    public static DSAPublicKeyProto buildDSAPublicKeyProto(DSAPublicKey pub) {
        return buildDSAPublicKeyProto(pub.getParams().getP(),
                                      pub.getParams().getQ(),
                                      pub.getParams().getG(),
                                      pub.getY()); // don't ask me why java is so inconsistent (mrochlin)

    }

    /** Builds a DSAPublicKeyProto protobuf from the DSA parameters */
    public static DSAPublicKeyProto buildDSAPublicKeyProto(BigInteger p, 
                                                            BigInteger q,
                                                            BigInteger g,
                                                            BigInteger y) {

        DSAPublicKeyProto.Builder dsaBuilder = DSAPublicKeyProto.newBuilder();
        dsaBuilder.setP(p.toString());
        dsaBuilder.setQ(q.toString());
        dsaBuilder.setG(g.toString());
        dsaBuilder.setY(y.toString());
        return dsaBuilder.build();
    }


    /** Converts an AuthPath.UserLeafNode protobuf {@code uln} 
     * to a byte[].
     */
    public static byte[] ulnProtoToBytes(AuthPath.UserLeafNode uln){
        // TODO: add the generic blob of data and the change key fields
        byte[] pubKey = strToBytes(uln.getPublickey());
        byte[] usr = strToBytes(uln.getName());
        byte[] ep_add = longToBytes(uln.getEpochAdded());
        byte[] ep_changed = longToBytes(uln.getEpochChanged());
        byte[] auk = new byte[]{(byte)(uln.getAllowsUnsignedKeychange() ? 0x01 : 0x00)};
        byte[] apl = new byte[]{(byte)(uln.getAllowsPublicLookup() ? 0x01 : 0x00)};
        byte[] ck = convertDSAPubKey(uln.getChangeKey());
        byte[] sig = ClientUtils.intListToByteArr(new ArrayList<Integer>(uln.getSignatureList()));
        byte[] lastMsg = ClientUtils.intListToByteArr(new ArrayList<Integer>(uln.getLastMsgList()));



        byte[] leafBytes = new byte[pubKey.length+usr.length+ep_add.length+auk.length+
                                    apl.length+ep_changed.length+ck.length+sig.length+lastMsg.length];
    
        ByteBuffer arr = ByteBuffer.wrap(leafBytes);
        arr.put(usr);
        arr.put(pubKey);
        arr.put(ep_add);
        arr.put(ep_changed);
        arr.put(auk);
        arr.put(apl);
        arr.put(ck);
        arr.put(sig);
        arr.put(lastMsg);

        return arr.array();


    }

    /** Takes the hash of a user leaf node {@code ulnHash} and recomputes
     * the hashes of each given interior node on the authentication path
     * {@code inList} up to the root's left or right child and returns this hash
     */
    public static byte[] computeInteriorNodeProtoHashes(byte[] ulnHash,
                                                        ArrayList<AuthPath.InteriorNode> inList) {

        byte[] curHash = ulnHash;

        for(int i = 0; i < inList.size(); i++){
            AuthPath.InteriorNode in = inList.get(i);
            
            if(!in.hasPrunedchild() && !in.hasSubtree()){
                System.out.println("No pruned child at level: "+i);
                return null;
            }
            
            Hash pcHash = in.getSubtree();
            AuthPath.PrunedChild pcSide = in.getPrunedchild();
            ArrayList<Integer> pcHashList = new ArrayList<Integer>(pcHash.getHashList());

            if(pcHashList.size() != ClientUtils.HASH_SIZE_BYTES){
                System.out.println("Bad hash length");
                return null;
            }

            byte[] prunedChild = new byte[ClientUtils.HASH_SIZE_BYTES];
            for(int j = 0; j < pcHashList.size(); j++){
                prunedChild[j] = pcHashList.get(j).byteValue();
            }
            
            if(pcSide == AuthPath.PrunedChild.LEFT){
                curHash = ClientUtils.hashChildren(prunedChild, curHash);
            }
            else if(pcSide == AuthPath.PrunedChild.RIGHT){
                curHash = ClientUtils.hashChildren(curHash, prunedChild);
            }
         
        }

        // at this point, curHash should be the root node's direct child
        return curHash;

    }

    /** Takes the hash  {@code authPathHash} computed from an authentication path
     * and incorporates it into the root node {@code root} of an 
     * AuthPath.RootNode protobuf. Returns this root node as a byte[].
     */
    public static byte[] rootProtoToBytes(byte[] authPathHash, AuthPath.RootNode root){

        Hash pcHash = root.getSubtree();
        AuthPath.PrunedChild pcSide = root.getPrunedchild();
        ArrayList<Integer> pcHashList = new ArrayList<Integer>(pcHash.getHashList());
        
        if(pcHashList.size() != ClientUtils.HASH_SIZE_BYTES){
            System.out.println("Bad hash length");
            return null;
        }
        
        byte[] prunedChild = new byte[ClientUtils.HASH_SIZE_BYTES];
        for(int j = 0; j < pcHashList.size(); j++){
            prunedChild[j] = pcHashList.get(j).byteValue();
        }
        
        Hash prevHashProto = root.getPrev();
        ArrayList<Integer> prevHashList = new ArrayList<Integer>(
                                                                 prevHashProto.getHashList());

         if(prevHashList.size() != ClientUtils.HASH_SIZE_BYTES){
            System.out.println("Bad prev hash length");
            return null;
        }
        
        byte[] prevHash = new byte[ClientUtils.HASH_SIZE_BYTES];
        for(int j = 0; j < prevHashList.size(); j++){
            prevHash[j] = prevHashList.get(j).byteValue();
        }

        byte[] ep = longToBytes(root.getEpoch());

        byte[] rootBytes = new byte[authPathHash.length+prunedChild.length+
                                    prevHash.length+ep.length];
	
	ByteBuffer arr = ByteBuffer.wrap(rootBytes);

        if(pcSide == AuthPath.PrunedChild.LEFT){
            arr.put(prunedChild);
            arr.put(authPathHash);
        }
        else{
            arr.put(authPathHash);
            arr.put(prunedChild);
        }

	arr.put(prevHash);
	arr.put(ep);

        return arr.array();
    }

}
