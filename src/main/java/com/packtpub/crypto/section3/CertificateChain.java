package com.packtpub.crypto.section3;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.HttpsURLConnection;

/**
 *
 * @author Erik Costlow
 */
public class CertificateChain {

    public static void main(String[] args) throws MalformedURLException, IOException, CertificateNotYetValidException {
        URL url = new URL("https://www.packtpub.com");
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.connect();
        Certificate[] certs = conn.getServerCertificates();

        Arrays.stream(certs).forEach(CertificateChain::printCert);

        System.out.println("There are " + certs.length + " certificates.");
        Arrays.stream(certs).map(cert -> (X509Certificate) cert)
                .forEach(x509 -> System.out.println(x509.getIssuerDN().getName()));
        System.out.println("The final certificate is for: " + conn.getPeerPrincipal());
    }

    private static void printCert(Certificate cert) {
        System.out.println("Certificate is: " + cert);
        if (cert instanceof X509Certificate) {
            try {
                ((X509Certificate) cert).checkValidity();
                System.out.println("Certificate is active for current date");
            } catch (CertificateExpiredException e) {
                Logger.getLogger(CertificateChain.class.getName()).log(Level.SEVERE, "Expired", e);
            } catch (CertificateNotYetValidException e) {
                Logger.getLogger(CertificateChain.class.getName()).log(Level.SEVERE, "Not yet valid", e);
            }
        } else {
            System.err.println("Odd, looks like there is a new type of certificate.");
        }
    }
}
