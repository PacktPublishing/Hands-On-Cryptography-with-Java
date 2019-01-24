package com.packtpub.crypto.section5;

import com.packtpub.crypto.Util;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Erik Costlow
 */
public class FileEncryptor {
    private static final Logger LOG = Logger.getLogger(FileEncryptor.class.getSimpleName());

    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/CBC/PKCS5PADDING";

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {
        
        //This snippet is literally copied from SymmetrixExample
        SecureRandom sr = new SecureRandom();
        byte[] key = new byte[16];
        sr.nextBytes(key); // 128 bit key
        byte[] initVector = new byte[16];
        sr.nextBytes(initVector); // 16 bytes IV
        System.out.println("Random key=" + Util.bytesToHex(key));
        System.out.println("initVector=" + Util.bytesToHex(initVector));
        IvParameterSpec iv = new IvParameterSpec(initVector);
        SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

        //Look for files here
        final Path tempDir = Files.createTempDirectory("packt-crypto");
        
        final Path encryptedPath = tempDir.resolve("1 - Encrypting and Decrypting files.pptx.encrypted");
        try (InputStream fin = FileEncryptor.class.getResourceAsStream("1 - Encrypting and Decrypting files.pptx");
                OutputStream fout = Files.newOutputStream(encryptedPath);
                CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher) {
        }) {
            final byte[] bytes = new byte[1024];
            for(int length=fin.read(bytes); length!=-1; length = fin.read(bytes)){
                cipherOut.write(bytes, 0, length);
            }
        } catch (IOException e) {
            LOG.log(Level.INFO, "Unable to encrypt", e);
        }
        
        LOG.info("Encryption finished, saved at " + encryptedPath);
        
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
        final Path decryptedPath = tempDir.resolve("1 - Encrypting and Decrypting files_decrypted.pptx");
        try(InputStream encryptedData = Files.newInputStream(encryptedPath);
                CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher);
                OutputStream decryptedOut = Files.newOutputStream(decryptedPath)){
            final byte[] bytes = new byte[1024];
            for(int length=decryptStream.read(bytes); length!=-1; length = decryptStream.read(bytes)){
                decryptedOut.write(bytes, 0, length);
            }
        } catch (IOException ex) {
            Logger.getLogger(FileEncryptor.class.getName()).log(Level.SEVERE, "Unable to decrypt", ex);
        }
        
        LOG.info("Decryption complete, open " + decryptedPath);
    }
}
