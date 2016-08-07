package org.coniks.crypto;

import org.junit.Test;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Unit tests for Signing.
 */
public class SigningTest
{

    @Test
    public void testRsaSignVerify()
        throws NoSuchAlgorithmException {

        KeyPair pair = Keys.generateRSAKeyPair();

        byte[] msg = "message".getBytes();

        byte[] sig = Signing.rsaSign(Keys.getRSAPrivate(pair), msg);

        assertTrue("RSA signature of message using same key pair can be verified",
                   Signing.rsaVerify(Keys.getRSAPublic(pair), msg, sig));
    }

    @Test
    public void testDsaSignVerify()
        throws NoSuchAlgorithmException {

        KeyPair pair = Keys.generateDSAKeyPair();

        byte[] msg = "message".getBytes();

        byte[] sig = Signing.dsaSign(Keys.getDSAPrivate(pair), msg);

        assertTrue("DSA signature of message using same key pair can be verified",
                   Signing.dsaVerify(Keys.getDSAPublic(pair), msg, sig));
    }
}
