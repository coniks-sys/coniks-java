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

import org.junit.Test;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.fail;

import java.nio.ByteBuffer;
import java.util.Random;

/**
 * Unit tests for Convert.
 */
public class ConvertTest {

    @Test
    public void testBytesToHex() {

        byte[] rand = new byte[4];
        new Random().nextBytes(rand);

        String conv = Convert.bytesToHex(rand);

        assertTrue("Bad length of hex string", conv.length() == 8);

        byte[] b = new byte[4];

        try {
            b[0] = (byte)Integer.parseInt(conv.substring(0, 2), 16);
            b[1] = (byte)Integer.parseInt(conv.substring(2, 4), 16);
            b[2] = (byte)Integer.parseInt(conv.substring(4, 6), 16);
            b[3] = (byte)Integer.parseInt(conv.substring(6, 8), 16);
        }
        catch (NumberFormatException e) {
            fail("Conversion of bytes to hex string failed - "+e.getMessage());
        }

        assertArrayEquals("Conversion of bytes to hex string failed",
                          rand, b);
    }

    @Test
    public void testBitsBytesConvert() {

        Random r = new Random();

        boolean[] bits = new boolean[32];
        for (int i = 0; i < bits.length; i++) {
            bits[i] = r.nextBoolean();
        }

        // convert bits to byte array
        byte[] bytes = new byte[4];
        for (int i = 0;i < bits.length; i++) {
            if (bits[i]) {
                bytes[i/8] |= (1 << 7) >> (i%8);
            }
        }

        for (int i = 0; i < bits.length; i++) {
            if (Convert.getNthBit(bytes, i) != bits[i]) {
                fail("Conversion of bytes to bits failed at bit "+i);
            }
        }

    }

    @Test
    public void testLongToBytes() {

        // test positive long
        long num = 42;
        byte[] bytes = Convert.longToBytes(num);

        assertTrue("Bad length of long byte array", bytes.length == 8);

        // need to flip the bytes to get right endianness back
        long l = ByteBuffer.wrap(bytes).getLong();
        assertTrue("Conversion of non-neg long to bytes failed: l = "+l,
                   num == l);

        // test negative long
        num = -42;
        bytes = Convert.longToBytes(num);

        l = ByteBuffer.wrap(bytes).getLong();
        assertTrue("Conversion of negative long to bytes failed: l = "+l,
                   num == l);
    }
}
