package com.packtpub.crypto.section3;

import com.packtpub.crypto.Util;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;

/**
 *
 * @author Erik Costlow
 */
public class AsymmetricDemo {

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SignatureException {
        final String original = "Encrypted example from Packt crypto course.";
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair alice = keyPairGenerator.generateKeyPair();
        //In this example, Alice is writing a message to herself. Not to Bob.

        final String cipherName = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
        //Can use other cipher names, like "RSA/ECB/PKCS1Padding"
        Cipher cipher = Cipher.getInstance(cipherName);
        cipher.init(Cipher.ENCRYPT_MODE, alice.getPublic());

        final byte[] originalBytes = original.getBytes(StandardCharsets.UTF_8);
        byte[] cipherTextBytes = cipher.doFinal(originalBytes);

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(alice.getPrivate());
        sig.update(originalBytes);
        byte[] signatureBytes = sig.sign();
        
        // Decrypt
        cipher.init(Cipher.DECRYPT_MODE, alice.getPrivate());
        byte[] decryptedBytes = cipher.doFinal(cipherTextBytes);
        String decryptedString = new String(decryptedBytes, StandardCharsets.UTF_8);

        System.out.println("Original:\t" + original);
        System.out.println("Encrypted:\t" + Util.bytesToHex(cipherTextBytes));
        System.out.println("Decrypted:\t" + decryptedString);
        if(!decryptedString.equals(original)){
            throw new IllegalArgumentException("Encrypted and decrypted text do not match");
        }
        
        System.out.println("Checking signature...");
        sig.initVerify(alice.getPublic());
        sig.update(decryptedBytes);
        final boolean signatureValid = sig.verify(signatureBytes);
        if(signatureValid){
            System.out.println("Signature checks out; written by key owner.");
        }else{
            throw new IllegalArgumentException("Signature does not match");
        }
    }
}
