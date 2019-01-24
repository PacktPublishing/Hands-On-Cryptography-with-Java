package com.packtpub.crypto.section2;

import com.packtpub.crypto.Util;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 *
 * @author Erik Costlow
 */
public class HashingPlain {

    /**
     * Produce the hash of this compiled class file.
     *
     * @param args
     * @throws NoSuchAlgorithmException
     */
    public static void main(String[] args) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try (InputStream in = HashingPlain.class.getResourceAsStream(HashingPlain.class.getSimpleName() + ".class")) {
            final byte[] bytes = new byte[1024];
            for (int length = in.read(bytes); length != -1; length = in.read(bytes)) {
                md.update(bytes, 0, length);
            }
        } catch (IOException e) {

        }

        final byte[] hashed = md.digest();
        System.out.println("The SHA-256 value is " + Util.bytesToHex(hashed));
    }

}
