package org.coniks.coniks_test_client;

import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.RSAPublicKeySpec;
import java.security.cert.CertificateException;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Scanner;
import java.io.PrintWriter;
import java.io.*;

public class KeyOps{

    //public static HashMap<Integer,DSAPublicKey> serverKeyStore;

    public static KeyPair generateDSAKeyPair(){

        KeyPairGenerator kg;
        
        try{
            kg = KeyPairGenerator.getInstance("DSA");
            kg.initialize(1024, new SecureRandom());
        }
        catch(NoSuchAlgorithmException e){
            System.out.println("DSA is not valid for some reason.");
            return null;
        }
        catch(InvalidParameterException e){
            System.out.println("DSA is not valid for some reason.");
            return null;
        }

        KeyPair kp = kg.generateKeyPair();

        return kp;

    } //ends generateKeyPair()
    

    /** Load the server's private key for commitment signing purposes 
     *
     *@param ksName the name of the keystore containing the server's signing key
     *@param pwdStr the password to the keystore
     */
    // public static RSAPrivateKey loadSigningKey(ServerConfig config){

    //     KeyStore ks = null;
    //     RSAPrivateKey myPrivateKey = null;

    //     try{
    //         ks = KeyStore.getInstance(KeyStore.getDefaultType());

    //         // get user password and file input stream
    //         char[] ks_password = config.KEYSTORE_PWD.toCharArray();
            
    //         FileInputStream fis = null;
      
    //         fis = new FileInputStream(config.KEYSTORE_PATH);
    //         ks.load(fis, ks_password);

    //         if(ks.isKeyEntry(config.NAME)){
    //             KeyStore.ProtectionParameter protParam = 
    //                 new KeyStore.PasswordProtection(ks_password);

    //             KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
    //                 ks.getEntry(config.NAME, protParam);
    //             myPrivateKey = (RSAPrivateKey)pkEntry.getPrivateKey();
    //         }
    //         else{
    //             throw new CertificateException();
    //         }
    //         fis.close();
    //         return myPrivateKey;
    //     }
    //     catch(IOException e){
    //         TimerLogger.error("KeyOps:loadSigningKey: Problem loading the keystore");
    //     }   
    //     catch(NoSuchAlgorithmException e){
    //         TimerLogger.error("KeyOps:loadSigningKey: Problem with integrity check algorithm");
    //     }
    //     catch(CertificateException e){
    //         TimerLogger.error("KeyOps:loadSigningKey: Problem with the cert(s) in keystore");
    //     }   
    //     catch(KeyStoreException e){
    //         TimerLogger.error("KeyOps:loadSigningKey: Problem getting Keystore instance");
    //     }
    //     catch(UnrecoverableEntryException e){
    //         TimerLogger.error("KeyOps:loadSigningKey: specified protParam were insufficient or invalid");
    //     }
    //     return null;
    // }

    //  * Load a server's public key for commitment verification purposes 
    //  *
    //  *@param config the server configuration containing the relevant information
    //  *@param keyOwner the entity which owns the public key to be loaded
     
    // public static RSAPublicKey loadPublicKey(ServerConfig config, String keyOwner){

    //     KeyStore ks = null;
    //     RSAPublicKey publicKey = null;

    //     try{
    //         ks = KeyStore.getInstance(KeyStore.getDefaultType());

    //         char[] ts_password = config.TRUSTSTORE_PWD.toCharArray();
            
    //         FileInputStream fis = null;
      
    //         fis = new FileInputStream(config.TRUSTSTORE_PATH);
    //         ks.load(fis, ts_password);

    //         if(ks.isKeyEntry(keyOwner)){
    //             KeyStore.ProtectionParameter protParam = 
    //                 new KeyStore.PasswordProtection(ts_password);

    //             KeyStore.TrustedCertificateEntry pkEntry = (KeyStore.TrustedCertificateEntry)
    //                 ks.getEntry(keyOwner, protParam);
    //             publicKey = (RSAPublicKey)pkEntry.getTrustedCertificate().getPublicKey();
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

    /** This is a really bad function that takes a string we assume contains a DSA key in 
        a poorly designed format, and returns the parameters if it can */
    public static BigInteger[] getDSAParamsFromString(String s) {
        // This method assumes that the key is written in a particular format
        // If it isn't, it will just return null
        // This should really only be used in testing
        try {
            int startp = s.indexOf('p');
            if (startp < 0) return null;
            int poundsym = s.indexOf('#', startp);
            if (poundsym < 0) return null;
            int poundsymend = s.indexOf('#', poundsym);
            if (poundsymend < 0) return null;
            int name_end = s.indexOf("-", poundsym);
            if (name_end > 0) poundsym = name_end;
            String ps = s.substring(poundsym + 1, poundsymend);
            BigInteger p = new BigInteger(ps);

            int startq = s.indexOf('q', poundsymend);
            if (startq < 0) return null;
            poundsym = s.indexOf('#', startq);
            if (poundsym < 0) return null;
            poundsymend = s.indexOf('#', poundsym);
            if (poundsymend < 0) return null;
            String qs = s.substring(poundsym + 1, poundsymend);
            BigInteger q = new BigInteger(qs);

            int startg = s.indexOf('g', poundsymend);
            if (startg < 0) return null;
            poundsym = s.indexOf('#', startg);
            if (poundsym < 0) return null;
            poundsymend = s.indexOf('#', poundsym);
            if (poundsymend < 0) return null;
            String gs = s.substring(poundsym + 1, poundsymend);
            BigInteger g = new BigInteger(gs);

            int starty = s.indexOf('y', poundsymend);
            if (starty < 0) return null;
            poundsym = s.indexOf('#', starty);
            if (poundsym < 0) return null;
            poundsymend = s.indexOf("))", poundsym);
            if (poundsymend < 0) return null;
            String ys = s.substring(poundsym + 1, poundsymend);
            BigInteger y = new BigInteger(ys);

            BigInteger[] arr = {p, q, g, y};
            return arr;
        }
        catch (IndexOutOfBoundsException e) {
            return null;
        }
        catch (NumberFormatException e) {
            return null;
        }
    }

    /*public static void loadKeyStore(){
    serverKeyStore = new HashMap<Integer,RSAPublicKey>();

    try{
        Scanner in = new Scanner(new File("crypto/serverKeys.ks"));

        while(in.hasNextLine()){
        String entry = in.nextLine();
        String[] keyInfo = entry.split(" ");

        if(keyInfo.length != 3){
            System.out.println("Bad keystore entry. Length is "+keyInfo.length+" "+entry);
            return;
        }

        int prid = Integer.parseInt(keyInfo[0]);
        BigInteger pubExp = new BigInteger(keyInfo[1]);
        BigInteger pubMod = new BigInteger(keyInfo[2]);

        RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(pubMod,pubExp);

        KeyFactory kf = KeyFactory.getInstance("RSA");
        
        RSAPublicKey pubKey = (RSAPublicKey)kf.generatePublic(pubKeySpec);

        serverKeyStore.put(prid, pubKey);
        
        }
        in.close();
    }
    catch(Exception e){
        e.printStackTrace();
    }
    
    } //ends loadKeyStore()

    public static void saveKeyStore(){

    try{
        PrintWriter out = new PrintWriter(new File("crypto/serverKeys.ks"));

        for(Integer prid : serverKeyStore.keySet()){
        RSAPublicKey pubKey = serverKeyStore.get(prid);

        String entry = ""+prid+" "+pubKey.getPublicExponent()+" "+pubKey.getModulus();
    
        out.println(entry);
        }
        out.flush();
        out.close();
    }
    catch(Exception e){
        e.printStackTrace();
    }
    
    } //ends saveKeyStore()
    
    public static void registerServerKey(int prid, RSAPublicKey pubKey){
    if(serverKeyStore != null){
        serverKeyStore.put(prid, pubKey);
        //System.out.println("Key for server "+prid+" successfully registered");
    }
    } //ends registerServerKey()

    public static void clearKeyStore(){
    if(serverKeyStore != null){
        serverKeyStore.clear();
        saveKeyStore();
    }
    }
    
    public static void printKeyStore(){
    if(serverKeyStore != null){
        for(Integer prid : serverKeyStore.keySet()){
        RSAPublicKey pubKey = serverKeyStore.get(prid);
        
        String entry = ""+prid+": "+pubKey.getPublicExponent()+" "+pubKey.getModulus();
        
        System.out.println(entry);
        }
    }
        } //ends printKeyStore()*/

} // ends KeyOps class
