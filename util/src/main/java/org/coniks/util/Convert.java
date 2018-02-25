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

package org.coniks.util;

import java.nio.charset.Charset;

/** Implements various utility conversion functions
 * used by various components of CONIKS.
 *
 *@author Marcela S. Melara (melara@cs.princeton.edu)
 *@author Aaron Blankstein
 *@author Michael Rochlin
 */
public class Convert {

    private static final char[] hexArray = "0123456789ABCDEF".toCharArray();

    // from Stackoverflow 9655181
     /** Converts a {@code byte[]} into a String
     * of its hexadecimal representation.
     *
     *@return The hex representation of {@code bytes} as a String.
     */
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
     */
    public static byte[] strToBytes (String str) {
        return str.getBytes(Charset.forName("UTF-8"));
    }

     /** Converts a long {@code val} into an array of bytes.
     *
     *@return The {@code byte[]} representation of the long value.
     */
    public static byte[] longToBytes(long val) {
        byte[] byteArr = new byte[8];

        for(int i = 7; i >= 0; i--) {
            byteArr[i] = (byte)(val & 0xFF);
            val >>= 8;
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

    /** Converts a byte array into an array of bits.
     *
     *@param buf the byte buffer to convert.
     *@return a boolean array representing each bit of the
     * given byte array.
     */
    public static boolean[] bytesToBits(byte[] buf) {
        boolean[] bits = new boolean[buf.length*8];
        for (int i = 0; i < bits.length; i++) {
            bits[i] = (buf[i/8] & (1 << (7 - (i%8)))) != 0;
        }
        return bits;
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

}
