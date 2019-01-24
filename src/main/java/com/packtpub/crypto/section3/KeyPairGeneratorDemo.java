package com.packtpub.crypto.section3;

import com.packtpub.crypto.Util;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * KeyPairGenerator (this one) is for asymmetric.
 *
 * @author Erik Costlow
 */
public class KeyPairGeneratorDemo {

    public static void main(String[] args) throws NoSuchAlgorithmException {
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        final KeyPair kp = kpg.generateKeyPair(); //The same as genKeyPair

        final PublicKey publicKey = kp.getPublic();
        final PrivateKey privateKey = kp.getPrivate();

        System.out.println("Public key is " + publicKey);
        System.out.println(" Our Hex-Encoded is " + Util.bytesToHex(publicKey.getEncoded()));
        System.out.println("Private key is " + privateKey);
    }
}
