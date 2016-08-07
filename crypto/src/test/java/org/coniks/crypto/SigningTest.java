package org.coniks.crypto;

import org.junit.Test;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.*;

/**
 * Unit tests for Signing.
 */
public class SigningTest
{

    @Test
    public void testRsaSignVerify() 
        throws NoSuchAlgorithmException {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);

        KeyPair pair = gen.generateKeyPair();

        byte[] msg = "message".getBytes();

        byte[] sig = Signing.rsaSign((RSAPrivateKey)pair.getPrivate(), msg);

        assertTrue("RSA signature of message using same key pair can be verified", Signing.rsaVerify((RSAPublicKey)pair.getPublic(), msg, sig));
    }

    @Test
    public void testDsaSignVerify() 
        throws NoSuchAlgorithmException {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("DSA");
        gen.initialize(1024);

        KeyPair pair = gen.generateKeyPair();

        byte[] msg = "message".getBytes();

        byte[] sig = Signing.dsaSign((DSAPrivateKey)pair.getPrivate(), msg);

        assertTrue("DSA signature of message using same key pair can be verified", Signing.dsaVerify((DSAPublicKey)pair.getPublic(), msg, sig));
    }
}
