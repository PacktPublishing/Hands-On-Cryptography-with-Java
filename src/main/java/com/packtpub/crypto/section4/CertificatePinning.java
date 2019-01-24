package com.packtpub.crypto.section4;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.TrustManagerFactory;

/**
 *
 * @author Erik Costlow
 */
public class CertificatePinning {

    public static void main(String[] args) throws MalformedURLException, IOException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, CertificateException {
        final String hostname = "https://www.packtpub.com";
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        KeyManager[] keyManagers = {};
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        KeyStore truststore = KeyStore.getInstance(KeyStore.getDefaultType());
        truststore.load(CertificatePinning.class.getResourceAsStream("keystore"), "changeit".toCharArray());
        trustManagerFactory.init(truststore);
        sslContext.init(keyManagers, trustManagerFactory.getTrustManagers(), new SecureRandom());

        final URL url = new URL(hostname);
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setSSLSocketFactory(sslContext.getSocketFactory());
        System.out.println("Testing connection with one certificate...");
        System.out.println("  Commands to test are in createkeystore.txt");
        try {
            conn.connect();
            System.out.println("Connected");
            try (InputStream in = conn.getInputStream()) {
                final ByteArrayOutputStream bout = new ByteArrayOutputStream();
                final byte[] bytes = new byte[1024];
                
                //I don't want to read the full html but this will do it.
                //for (int length = in.read(bytes); length != -1; length = in.read(bytes)) {
                //    bout.write(bytes, 0, length);
                //}
                final int length = in.read(bytes);
                bout.write(bytes, 0, length);
                System.out.println(new String(bout.toByteArray()));
            }
        } catch (SSLHandshakeException e) {
            Logger.getLogger(CertificatePinning.class.getSimpleName()).log(Level.SEVERE, "Certificate pin missing", e);
        } catch (SSLException e) {
            Logger.getLogger(CertificatePinning.class.getSimpleName()).log(Level.SEVERE, "Unable to access valid keystore", e);
        }
    }
}
