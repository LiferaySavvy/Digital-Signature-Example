package com.meera.ds;
import java.io.*;
import java.security.*;
import java.security.spec.*;

class VerSig {

    public static void main(String[] args) {

        /* Verify a DSA signature */

      try {

        // the rest of the code goes here
        	FileInputStream keyfis = new FileInputStream("D:/examples/suepk");
        	byte[] encKey = new byte[keyfis.available()];  
        	keyfis.read(encKey);
        	keyfis.close();
        	X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);
        	KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");
        	PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
        	FileInputStream sigfis = new FileInputStream("D:/examples/sig");
        	byte[] sigToVerify = new byte[sigfis.available()]; 
        	sigfis.read(sigToVerify);
        	sigfis.close();
        	Signature sig = Signature.getInstance("SHA1withDSA", "SUN");
        	sig.initVerify(pubKey);
        	FileInputStream datafis = new FileInputStream("D:/examples/meera.txt");
        	BufferedInputStream bufin = new BufferedInputStream(datafis);

        	byte[] buffer = new byte[1024];
        	int len;
        	while (bufin.available() != 0) {
        	    len = bufin.read(buffer);
        	    sig.update(buffer, 0, len);
        	};
        	bufin.close();
        	boolean verifies = sig.verify(sigToVerify);
        	System.out.println("signature verifies: " + verifies);

        } catch (Exception e) {
            System.err.println("Caught exception " + e.toString());
        }
    }

}