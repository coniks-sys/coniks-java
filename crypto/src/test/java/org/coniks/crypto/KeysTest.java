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

package org.coniks.crypto;

import org.junit.Test;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import static org.hamcrest.core.StringContains.containsString;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Unit tests for Keys.
 */
public class KeysTest
{

    @Test
    public void testGetDSAPrivateFail()
        throws NoSuchAlgorithmException {

        KeyPair pair = Keys.generateRSAKeyPair();

        try {
            DSAPrivateKey pk = Keys.getDSAPrivate(pair);
            fail("Expected a ClassCastException to be thrown");
        }
        catch(ClassCastException e) {
            assertThat(e.getMessage(),
                       containsString("sun.security.rsa.RSAPrivateCrtKeyImpl cannot be cast to java.security.interfaces.DSAPrivateKey"));
        }
    }

    @Test
    public void testGetDSAPublicFail()
        throws NoSuchAlgorithmException {

        KeyPair pair = Keys.generateRSAKeyPair();

        try {
            DSAPublicKey pk = Keys.getDSAPublic(pair);
            fail("Expected a ClassCastException to be thrown");
        }
        catch(ClassCastException e) {
            assertThat(e.getMessage(),
                       containsString("sun.security.rsa.RSAPublicKeyImpl cannot be cast to java.security.interfaces.DSAPublicKey"));
        }
    }

    @Test
    public void testGetRSAPrivateFail()
        throws NoSuchAlgorithmException {

        KeyPair pair = Keys.generateDSAKeyPair();

        try {
            RSAPrivateKey pk = Keys.getRSAPrivate(pair);
            fail("Expected a ClassCastException to be thrown");
        }
        catch(ClassCastException e) {
            assertThat(e.getMessage(),
                       containsString("sun.security.provider.DSAPrivateKey cannot be cast to java.security.interfaces.RSAPrivateKey"));
        }
    }

    @Test
    public void testGetRSAPublicFail()
        throws NoSuchAlgorithmException {

        KeyPair pair = Keys.generateDSAKeyPair();

        try {
            RSAPublicKey pk = Keys.getRSAPublic(pair);
            fail("Expected a ClassCastException to be thrown");
        }
        catch(ClassCastException e) {
            assertThat(e.getMessage(),
                       containsString("sun.security.provider.DSAPublicKeyImpl cannot be cast to java.security.interfaces.RSAPublicKey"));
        }
    }

}
