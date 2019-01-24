package com.packtpub.crypto.section2;

import com.packtpub.crypto.Util;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 *
 * @author Erik Costlow
 */
public class HashingWithSalt {

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {
        final String password = "12345";
        final String salt = "user@example.com";
        final int iterations = 32;
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), iterations, 512);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] hashed = skf.generateSecret(keySpec).getEncoded();
        
        System.out.println("The SHA-256 value salted with PBKDF2 is " + Util.bytesToHex(hashed));
    }
}
