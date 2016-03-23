package org.coniks.coniks_test_client;

// import server.ServerConfig;
// import utils.*;

import java.security.*;
import java.security.KeyPair;
import java.security.spec.*;
import java.security.interfaces.*;
import javax.crypto.*;
import java.math.BigInteger;

// TODO(mrochlin)
// Should use protected keystore instead of just file streams
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;


public class SignatureOps{

    private static ClientConfig CONFIG = null;

    public static void initSignatureOps(ClientConfig config){
        CONFIG = config;
    }


    // public static DSAPrivateKey loadPublicKey(ClientConfig config, String keyOwner){

    //     KeyStore ks = null;
    //     DSAPrivateKey publicKey = null;

    //     try{
    //         ks = KeyStore.getInstance(KeyStore.getDefaultType());

    //         char[] ts_password = config.PRIVATE_KEYSTORE_PWD.toCharArray();
            
    //         FileInputStream fis = null;
      
    //         fis = new FileInputStream(config.PRIVATE_KEYSTORE_PATH);
    //         ks.load(fis, ts_password);

    //         if(ks.isKeyEntry(keyOwner)){
    //             KeyStore.ProtectionParameter protParam = 
    //                 new KeyStore.PasswordProtection(ts_password);

    //             KeyStore.TrustedCertificateEntry pkEntry = (KeyStore.TrustedCertificateEntry)
    //                 ks.getEntry(keyOwner, protParam);
    //             publicKey = (DSAPublicKey)pkEntry.getTrustedCertificate().getPublicKey();
    //         }
    //         else{
    //             throw new CertificateException();
    //         }
    //         fis.close();
    //         return publicKey;
    //     }
    //     catch(IOException e){
    //         ServerLogger.error("KeyOps:loadPublicKey: Problem loading the keystore");
    //     }   
    //     catch(NoSuchAlgorithmException e){
    //         ServerLogger.error("KeyOps:loadPublicKey: Problem with integrity check algorithm");
    //     }
    //     catch(CertificateException e){
    //         ServerLogger.error("KeyOps:loadPublicKey: Problem with the cert(s) in keystore");
    //     }   
    //     catch(KeyStoreException e){
    //         ServerLogger.error("KeyOps:loadPublicKey: Problem getting Keystore instance");
    //     }
    //     catch(UnrecoverableEntryException e){
    //         ServerLogger.error("KeyOps:loadPublicKey: specified protParam were insufficient or invalid");
    //     }
    //     return null;
    // }


    /*********************************************************************
     * The following code is used in the reference client, but does not 
     * use a keystore. Instead these functions simply use regular, unprotected
     * files. Future implmentations should use protected keystores 
     *********************************************************************/


    // TODO(mrochlin)
    // Should use protected keystore instead of just file streams
    public static boolean unsafeSaveDSAKeyPair(KeyPair kp) {
        if (CONFIG == null) initSignatureOps(new ClientConfig());
        return unsafeSaveDSAKeyPairToFile(kp, CONFIG.PRIVATE_KEYSTORE_PATH);
    }

    // TODO(mrochlin)
    // Should use protected keystore instead of just file streams
    public static boolean unsafeSavePublicKey(DSAPublicKey pubKey) {
        if (CONFIG == null) initSignatureOps(new ClientConfig());
        return unsafeSavePublicKeyToFile(pubKey, CONFIG.PRIVATE_KEYSTORE_PATH + "_pub");
    }

    // TODO(mrochlin)
    // Should use protected keystore instead of just file streams
    public static boolean unsafeSavePrivateKey(DSAPrivateKey prKey) {
        if (CONFIG == null) initSignatureOps(new ClientConfig());
        return unsafeSavePrivateKeyToFile(prKey, CONFIG.PRIVATE_KEYSTORE_PATH + "_pr");
    }

    // TODO(mrochlin)
    // Should use protected keystore instead of just file streams
    public static boolean unsafeSaveDSAKeyPair(KeyPair kp, String username) {
        if (CONFIG == null) initSignatureOps(new ClientConfig());
        String pubPath = CONFIG.PRIVATE_KEYSTORE_PATH + "_" + username + "_pub";
        String prPath = CONFIG.PRIVATE_KEYSTORE_PATH + "_" + username + "_pr";
        System.out.println("Saving to: " + pubPath + " " + prPath);
        return unsafeSavePublicKeyToFile((DSAPublicKey) kp.getPublic(), pubPath) 
                && unsafeSavePrivateKeyToFile((DSAPrivateKey) kp.getPrivate(), prPath);
    }

    // TODO(mrochlin)
    // Should use protected keystore instead of just file streams
    public static boolean unsafeSavePublicKey(DSAPublicKey pubKey, String username) {
        if (CONFIG == null) initSignatureOps(new ClientConfig());
        return unsafeSavePublicKeyToFile(pubKey, CONFIG.PRIVATE_KEYSTORE_PATH + "_" + username + "_pub");
    }

    // TODO(mrochlin)
    // Should use protected keystore instead of just file streams
    public static boolean unsafeSavePrivateKey(DSAPrivateKey prKey, String username) {
        if (CONFIG == null) initSignatureOps(new ClientConfig());
        return unsafeSavePrivateKeyToFile(prKey, CONFIG.PRIVATE_KEYSTORE_PATH + "_" + username + "_pr");
    }



    // TODO(mrochlin)
    // Should use protected keystore instead of just file streams
    public static boolean unsafeSaveDSAKeyPairToFile(KeyPair kp, String filePath) {
        if (CONFIG == null) initSignatureOps(new ClientConfig());
        String pubPath = filePath + "_pub";
        String prPath = filePath + "_pr";
        return unsafeSavePublicKeyToFile((DSAPublicKey) kp.getPublic(), pubPath) 
                && unsafeSavePrivateKeyToFile((DSAPrivateKey) kp.getPrivate(), prPath);
    }

    // TODO(mrochlin)
    // Should use protected keystore instead of just file streams
    public static boolean unsafeSavePublicKeyToFile(DSAPublicKey pubKey, String fileName) {
        if (CONFIG == null) initSignatureOps(new ClientConfig());
        try {
            ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(fileName));
            out.writeObject(pubKey);
            out.close();
        }
        catch (Exception e) {
            return false;
        }
        return true;
    }

    // TODO(mrochlin)
    // Should use protected keystore instead of just file streams
    public static boolean unsafeSavePrivateKeyToFile(DSAPrivateKey prKey, String fileName) {
        if (CONFIG == null) initSignatureOps(new ClientConfig());
        try {
            ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(fileName));
            out.writeObject(prKey);
            out.close();
        }
        catch (Exception e) {
            return false;
        }
        return true;
    }


    // // TODO(mrochlin)
    // // Should use protected keystore instead of just file streams
    // public static boolean unsafeSavePublicKey(DSAPublicKey pubKey, String fileName, String username) {
    //     try {
    //         ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(fileName));
    //         out.writeObject(pubKey);
    //         out.close();
    //     }
    //     catch (Exception e) {
    //         return false;
    //     }
    //     return true;
    // }

    // // TODO(mrochlin)
    // // Should use protected keystore instead of just file streams
    // public static boolean unsafeSavePrivateKey(DSAPrivateKey prKey, String fileName, String username) {
    //     try {
    //         ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(fileName));
    //         out.writeObject(prKey);
    //         out.close();
    //     }
    //     catch (Exception e) {
    //         return false;
    //     }
    //     return true;
    // }

    // TODO(mrochlin)
    // Should use protected keystore instead of just file streams
    public static KeyPair unsafeLoadDSAKeyPair() {
        if (CONFIG == null) initSignatureOps(new ClientConfig());
        return unsafeLoadDSAKeyPairFromFile(CONFIG.PRIVATE_KEYSTORE_PATH + "_pub", 
                                            CONFIG.PRIVATE_KEYSTORE_PATH + "_pr");
    }

    // TODO(mrochlin)
    // Should use protected keystore instead of just file streams
    public static DSAPublicKey unsafeLoadDSAPublicKey() {
        if (CONFIG == null) initSignatureOps(new ClientConfig());
        return unsafeLoadDSAPublicKeyFromFile(CONFIG.PRIVATE_KEYSTORE_PATH + "_pub");
    }

    // TODO(mrochlin)
    // Should use protected keystore instead of just file streams
    public static DSAPrivateKey unsafeLoadDSAPrivateKey() {
        if (CONFIG == null) initSignatureOps(new ClientConfig());
        return unsafeLoadDSAPrivateKeyFromFile(CONFIG.PRIVATE_KEYSTORE_PATH + "_pr");
    }

    // TODO(mrochlin)
    // Should use protected keystore instead of just file streams
    public static KeyPair unsafeLoadDSAKeyPair(String username) {
        if (CONFIG == null) initSignatureOps(new ClientConfig());
        return unsafeLoadDSAKeyPairFromFile(CONFIG.PRIVATE_KEYSTORE_PATH + "_" + username + "_pub", 
                                    CONFIG.PRIVATE_KEYSTORE_PATH + "_" + username + "_pr");
    }

    // TODO(mrochlin)
    // Should use protected keystore instead of just file streams
    public static DSAPublicKey unsafeLoadDSAPublicKey(String username) {
        if (CONFIG == null) initSignatureOps(new ClientConfig());
        return unsafeLoadDSAPublicKeyFromFile(CONFIG.PRIVATE_KEYSTORE_PATH + "_" + username + "_pub");
    }

    // TODO(mrochlin)
    // Should use protected keystore instead of just file streams
    public static DSAPrivateKey unsafeLoadDSAPrivateKey(String username) {
        if (CONFIG == null) initSignatureOps(new ClientConfig());
        return unsafeLoadDSAPrivateKeyFromFile(CONFIG.PRIVATE_KEYSTORE_PATH + "_" + username + "_pr");
    }


    // TODO(mrochlin)
    // Should use protected keystore instead of just file streams
    public static KeyPair unsafeLoadDSAKeyPairFromFile(String pubKeyFile, String prKeyFile) {
        if (CONFIG == null) initSignatureOps(new ClientConfig());
        DSAPublicKey pubKey = unsafeLoadDSAPublicKeyFromFile(pubKeyFile);
        DSAPrivateKey prKey = unsafeLoadDSAPrivateKeyFromFile(prKeyFile);
        if (pubKey == null || prKey == null) {
            return null;
        }
        return new KeyPair((PublicKey) pubKey, (PrivateKey) prKey);
    }

    // TODO(mrochlin)
    // Should use protected keystore instead of just file streams
    public static DSAPublicKey unsafeLoadDSAPublicKeyFromFile(String pubKeyFile) {
        if (CONFIG == null) initSignatureOps(new ClientConfig());
        try {
            ObjectInputStream keyIn = new ObjectInputStream(new FileInputStream(pubKeyFile));
            DSAPublicKey pubKey = (DSAPublicKey) keyIn.readObject();
            keyIn.close();
            return pubKey;
        }
        catch (Exception e) {
            return null;
        }
    }

    // TODO(mrochlin)
    // Should use protected keystore instead of just file streams
    public static DSAPrivateKey unsafeLoadDSAPrivateKeyFromFile(String prKeyFile) {
        if (CONFIG == null) initSignatureOps(new ClientConfig());
        try {
            ObjectInputStream keyIn = new ObjectInputStream(new FileInputStream(prKeyFile));
            DSAPrivateKey prKey = (DSAPrivateKey) keyIn.readObject();
            keyIn.close();
            return prKey;
        }
        catch (Exception e) {
            return null;
        }
    }


    // digitally sign a given array of bytes
    // public static byte[] sign(byte[] input){

    //     RSAPrivateKey MY_PRIV_KEY = KeyOps.loadSigningKey(CONFIG);

    // byte[] signed = null;

    //     if(MY_PRIV_KEY == null){
    //     throw new RuntimeException("borked pk?");
    //     }
    
    // try{
    //     Signature signer = Signature.getInstance("SHA256withRSA");
    //     signer.initSign(MY_PRIV_KEY, new SecureRandom());
    //         signer.update(input);
            
    //     signed = signer.sign();
    //     return signed;
    // }
    // catch(NoSuchAlgorithmException e){
    //     System.out.println("RSA is invalid for some reason.");
    // }
    // catch(InvalidKeyException e){
    //     System.out.println("The given key is invalid.");
    // }
    //     catch(SignatureException e){
    //     System.out.println("The format of the input is invalid.");
    // }
    
    // return signed;
    // }

    // // verify the specified key owner's (i.e. server's) signature on the given message 
    // public static boolean verifySig(byte[] msg, byte[] signature, String keyOwner){

    //     RSAPublicKey pubKey = KeyOps.loadPublicKey(CONFIG, keyOwner);

    // try{

    //     Signature verifier = Signature.getInstance("SHA256withRSA");
    //     verifier.initVerify(pubKey);
    //     verifier.update(msg);
        
    //     return verifier.verify(signature);
    // }
    // catch(NoSuchAlgorithmException e){
    //     System.out.println("SHA256withRSA is invalid for some reason.");
    // }
    // catch(InvalidKeyException e){
    //     System.out.println("The given key is invalid.");
    // }
    // catch(SignatureException e){
    //     System.out.println("The format of the input is invalid: "+e.getMessage());
    // }
    
    // return false;

    // }

    /** Makes a DSA PublicKey from the given parameters */
    public static PublicKey makeDSAPublicKeyFromParams(BigInteger p, BigInteger q, BigInteger g, BigInteger y) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("DSA");
            KeySpec publicKeySpec = new DSAPublicKeySpec(y, p, q, g);
            return keyFactory.generatePublic(publicKeySpec);
        }
        catch(InvalidParameterException e) {
            System.out.println("The given key is invalid.");
        }
        catch (InvalidKeySpecException e) {
            System.out.println("The given key params are invalid.");
        }
        catch(NoSuchAlgorithmException e){
            System.out.println("DSA is invalid for some reason.");
        }
        return null;
    }

    /** Verifies @code{msg} and the @code{sig} using the DSA PublicKey @code{pk} */
    public static boolean verifySigFromDSA(byte[] msg, byte[] sig, PublicKey pk) {
        try {
            Signature verifyalg = Signature.getInstance("DSA");
            verifyalg.initVerify(pk);
            verifyalg.update(msg);
            if (!verifyalg.verify(sig)) {
                System.out.println("Failed to validate signature");
                return false;
            }
            return true;
        }
        catch(NoSuchAlgorithmException e){
            System.out.println("DSA is invalid for some reason.");
        }
        catch(InvalidKeyException e){
            System.out.println("The given key is invalid.");
        }
        catch(SignatureException e){
            System.out.println("The format of the input is invalid: "+e.getMessage());
        }
        return false;
    }

    /** Signs @code{msg} using DSAPrivateKey @code{prk} 
        Returns null on an error 
        Throws @code{InvalidKeyException} if @code{prk} is null */
    public static byte[] sign(byte[] msg, DSAPrivateKey prk) throws InvalidKeyException {
        if (prk == null) {
            System.out.println("The given key is invalid.");
            throw new InvalidKeyException();
        }
        try {
            Signature sigProcess = Signature.getInstance("DSA");
            sigProcess.initSign(prk);
            sigProcess.update(msg);
            return sigProcess.sign();
        }
        catch(NoSuchAlgorithmException e){
            System.out.println("DSA is invalid for some reason.");
        }
        catch(InvalidKeyException e){
            System.out.println("The given key is invalid.");
        }
        catch(SignatureException e){
            System.out.println("The format of the input is invalid: "+e.getMessage());
        }
        return null;
    }


} //ends SignatureOps class
