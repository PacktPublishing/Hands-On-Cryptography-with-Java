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
 * Compare this against the AsymmetricDemo. Unlike that, this example can
 * exchange the message.
 *
 * @author Erik Costlow
 */
public class AsymmetricDemoWithBob {

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SignatureException {
        final String original = "Encrypted inter-personal example from Packt crypto course.";
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair alice = keyPairGenerator.generateKeyPair();
        KeyPair bob = keyPairGenerator.generateKeyPair();

        final String cipherName = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
        //Can use other cipher names, like "RSA/ECB/PKCS1Padding"
        Cipher cipher = Cipher.getInstance(cipherName);
        cipher.init(Cipher.ENCRYPT_MODE, bob.getPublic());

        final byte[] originalBytes = original.getBytes(StandardCharsets.UTF_8);
        byte[] cipherTextBytes = cipher.doFinal(originalBytes);

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(alice.getPrivate());
        sig.update(originalBytes);
        byte[] signatureBytes = sig.sign();

        // Decrypt
        cipher.init(Cipher.DECRYPT_MODE, bob.getPrivate());
        byte[] decryptedBytes = cipher.doFinal(cipherTextBytes);
        String decryptedString = new String(decryptedBytes, StandardCharsets.UTF_8);

        System.out.println("Original:\t" + original);
        System.out.println("Encrypted:\t" + Util.bytesToHex(cipherTextBytes));
        System.out.println("Decrypted:\t" + decryptedString);
        if (!decryptedString.equals(original)) {
            throw new IllegalArgumentException("Encrypted and decrypted text do not match");
        }

        System.out.println("Checking signature...");
        sig.initVerify(alice.getPublic());
        sig.update(decryptedBytes);
        final boolean signatureValid = sig.verify(signatureBytes);
        if (signatureValid) {
            System.out.println("Yes, Alice wrote this. Notice where Alice/Bob keys are used.");
        } else {
            throw new IllegalArgumentException("Signature does not match");
        }
    }
}
