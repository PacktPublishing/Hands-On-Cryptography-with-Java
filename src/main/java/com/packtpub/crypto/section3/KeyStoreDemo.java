package com.packtpub.crypto.section3;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 *
 * @author Erik Costlow
 */
public class KeyStoreDemo {

    public static void main(String[] args) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException, OperatorCreationException {
        final File keyStoreLocation;
        final KeyStore keyStore = KeyStore.getInstance("JKS");
        if(args.length == 0){
            keyStoreLocation = File.createTempFile("keystore", ".jks");
            keyStore.load(null, "changeit".toCharArray());
        }else{
            keyStoreLocation = new File(args[0]);
            keyStore.load(new FileInputStream(keyStoreLocation), "changeit".toCharArray());
        }
        
        System.out.println("Stored keystore to " + keyStoreLocation);

        System.out.println("Making a new KeyPair to put in it.");
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        final KeyPair kp = kpg.generateKeyPair();
        final Certificate wrapped = generateCertificate(kp);
        Entry entry = new PrivateKeyEntry(kp.getPrivate(), new Certificate[]{wrapped});

        keyStore.setEntry("mine", entry, new KeyStore.PasswordProtection("changeit".toCharArray()));

        keyStore.store(new FileOutputStream(keyStoreLocation), "changeit".toCharArray());
    }

    /**
     * It's annoying to have to wrap KeyPairs with Certificates, but this is
     * "easier" for you to know who the key belongs to.
     *
     * @param keyPair A KeyPair to wrap
     * @return A wrapped certificate with constant name
     * @throws CertificateException
     * @throws OperatorCreationException
     */
    public static Certificate generateCertificate(KeyPair keyPair) throws CertificateException, OperatorCreationException {
        X500Name name = new X500Name("cn=Annoying Wrapper");
        SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
        final Date start = new Date();
        final Date until = Date.from(LocalDate.now().plus(365, ChronoUnit.DAYS).atStartOfDay().toInstant(ZoneOffset.UTC));
        final X509v3CertificateBuilder builder = new X509v3CertificateBuilder(name,
                new BigInteger(10, new SecureRandom()), //Choose something better for real use
                start,
                until,
                name,
                subPubKeyInfo
        );
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").setProvider(new BouncyCastleProvider()).build(keyPair.getPrivate());
        final X509CertificateHolder holder = builder.build(signer);

        Certificate cert = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(holder);
        return cert;
    }
}
