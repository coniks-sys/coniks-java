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
            fail("Expected an ClassCastException to be thrown");
        }
        catch(ClassCastException e) {
            System.out.println(e.getMessage());
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
            fail("Expected an ClassCastException to be thrown");
        }
        catch(ClassCastException e) {
            System.out.println(e.getMessage());
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
            fail("Expected an ClassCastException to be thrown");
        }
        catch(ClassCastException e) {
            System.out.println(e.getMessage());
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
            fail("Expected an ClassCastException to be thrown");
        }
        catch(ClassCastException e) {
            System.out.println(e.getMessage());
            assertThat(e.getMessage(),
                       containsString("sun.security.provider.DSAPublicKeyImpl cannot be cast to java.security.interfaces.RSAPublicKey"));
        }
    }

}
