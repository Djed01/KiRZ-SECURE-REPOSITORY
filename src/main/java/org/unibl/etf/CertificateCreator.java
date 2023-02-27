package org.unibl.etf;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

public class CertificateCreator {

    void createCertificate(String username, String password) {
        Security.addProvider(new BouncyCastleProvider());
        try {
            // Generate a new RSA key pair for the certificate request
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            //  Create a certificate signing request (CSR) for the new certificate
            X500Name subject = new X500Name("CN="+username);
            PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                    subject,
                    keyPair.getPublic());

            JcaContentSignerBuilder csrBuilder = new JcaContentSignerBuilder("SHA256WithRSAEncryption");
            ContentSigner csrContentSigner = csrBuilder.build(keyPair.getPrivate());
            PKCS10CertificationRequest csr = p10Builder.build(csrContentSigner);

            //  Load the CA keystore
            KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
            FileInputStream inputStream = new FileInputStream("keystore.p12");
            keyStore.load(inputStream, "sigurnost".toCharArray());
            inputStream.close();

            //  Get the CA certificate and private key from the keystore
            X509Certificate caCert = (X509Certificate) keyStore.getCertificate("CARoot");
            PrivateKey caPrivateKey = (PrivateKey) keyStore.getKey("CARoot", "sigurnost".toCharArray());

            // Sign the CSR with the CA
            X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                    new X500Name(caCert.getSubjectDN().getName()),
                    BigInteger.valueOf(System.currentTimeMillis()),
                    new Date(System.currentTimeMillis()),
                    new Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24 * 183),
                    csr.getSubject(),
                    csr.getSubjectPublicKeyInfo());

            JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
            certBuilder.addExtension(
                    Extension.subjectKeyIdentifier,
                    false,
                    extensionUtils.createSubjectKeyIdentifier(keyPair.getPublic()));
            certBuilder.addExtension(
                    Extension.authorityKeyIdentifier,
                    false,
                    extensionUtils.createAuthorityKeyIdentifier(caCert));
            certBuilder.addExtension(
                    Extension.basicConstraints,
                    true,
                    new BasicConstraints(false));

            JcaContentSignerBuilder certSignerBuilder = new JcaContentSignerBuilder("SHA256WithRSAEncryption");
            ContentSigner certContentSigner = certSignerBuilder.build(caPrivateKey);
            X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certBuilder.build(certContentSigner));

            // Store the private key entry to the keystore
            PrivateKey certPrivateKey = keyPair.getPrivate();
            KeyStore.PrivateKeyEntry certPrivateKeyEntry = new KeyStore.PrivateKeyEntry(certPrivateKey, new java.security.cert.Certificate[]{cert});
            keyStore.setEntry(username, certPrivateKeyEntry, new KeyStore.PasswordProtection("sigurnost".toCharArray()));
            OutputStream keystoreStream = new FileOutputStream("keystore.p12");
            keyStore.store(keystoreStream, "sigurnost".toCharArray());
            keystoreStream.close();

            // Save the signed certificate to a file
            OutputStream outputStream = new FileOutputStream("./CERTIFICATES/"+username+".crt");
            outputStream.write(cert.getEncoded());
            outputStream.close();

        } catch (NoSuchAlgorithmException | NoSuchProviderException | CertificateException | KeyStoreException |
                 IOException | OperatorCreationException | UnrecoverableKeyException e) {
            e.printStackTrace();
        }
    }
}
