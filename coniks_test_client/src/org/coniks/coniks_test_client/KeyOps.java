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

/** Implements all operations involving encryption keys
 * that a CONIKS client must perform.
 *
 *@author Michael Rochlin
 */
public class KeyOps{

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

} // ends KeyOps class
