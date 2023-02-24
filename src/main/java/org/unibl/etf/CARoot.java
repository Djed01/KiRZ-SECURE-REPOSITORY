package org.unibl.etf;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.*;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.asn1.x509.CRLReason;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.util.Date;


public class CARoot {
    public void CreateCARoot() {
        Security.addProvider(new BouncyCastleProvider());

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            X500Name issuer = new X500Name("CN=My CA");
            X500Name subject = issuer; // CA's certificate is self-signed
            BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
            Date startDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
            Date endDate = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000);

            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    issuer,
                    serialNumber,
                    startDate,
                    endDate,
                    subject,
                    keyPair.getPublic());

            ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                    .setProvider("BC")
                    .build(keyPair.getPrivate());

            X509CertificateHolder certHolder = builder.build(contentSigner);
            X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);

            KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
            keyStore.load(null, null);

            keyStore.setKeyEntry("myca", keyPair.getPrivate(), "sigurnost".toCharArray(), new X509Certificate[] { cert });

            FileOutputStream outputStream = new FileOutputStream("keystore.p12");
            keyStore.store(outputStream, "sigurnost".toCharArray());
            outputStream.close();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | CertificateException | KeyStoreException |
                 IOException |
                 OperatorCreationException e) {
            e.printStackTrace();
        }
    }

    public void createCRL(){
        Security.addProvider(new BouncyCastleProvider());
        try {
            //  Load the CA keystore
            KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
            FileInputStream inputStream = new FileInputStream("keystore.p12");
            keyStore.load(inputStream, "sigurnost".toCharArray());
            inputStream.close();

            //  Get the CA certificate and private key from the keystore
            X509Certificate caCert = (X509Certificate) keyStore.getCertificate("myca");
            PrivateKey caPrivateKey = (PrivateKey) keyStore.getKey("myca", "sigurnost".toCharArray());

            X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(new X500Name(caCert.getSubjectDN().getName()), new Date());

            // Generate the CRL
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(caPrivateKey);
            X509CRLHolder crlHolder = crlBuilder.build(signer);

            // Saving the CRL to a file
            JcaX509CRLConverter converter = new JcaX509CRLConverter();
            X509CRL crl = converter.getCRL(crlHolder);
            byte[] crlBytes = crl.getEncoded();
            FileOutputStream fos = new FileOutputStream("crl.crl");
            fos.write(crlBytes);
            fos.close();

        }catch (NoSuchAlgorithmException | NoSuchProviderException | CertificateException | KeyStoreException |
                IOException | OperatorCreationException | UnrecoverableKeyException | CRLException e){
            e.printStackTrace();
        }

    }

    public void suspendCertificate(String alias){
        Security.addProvider(new BouncyCastleProvider());
        try {
            // Load the CA keystore
            KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
            FileInputStream keystoreStream = new FileInputStream("keystore.p12");
            keyStore.load(keystoreStream, "sigurnost".toCharArray());
            keystoreStream.close();

            // Get the CA certificate and private key from the keystore
            X509Certificate caCert = (X509Certificate) keyStore.getCertificate("myca");
            PrivateKey caPrivateKey = (PrivateKey) keyStore.getKey("myca", "sigurnost".toCharArray());

            // Load the CRL file
            InputStream inputStream = new FileInputStream("crl.crl");
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509CRL crl = (X509CRL) certificateFactory.generateCRL(inputStream);
            inputStream.close();

            // Get the certificate that should be revoked
            X509Certificate suspendedCert = (X509Certificate) keyStore.getCertificate("mynewcert");

            // Create a JcaX509CertificateHolder object from the CA certificate
            JcaX509CertificateHolder caCertHolder = new JcaX509CertificateHolder(caCert);

            // Create a new CRL builder and add the revoked certificate
            X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(caCertHolder.getIssuer(), new Date());
            crlBuilder.addCRLEntry(suspendedCert.getSerialNumber(),new Date(),CRLReason.CERTIFICATE_HOLD);

            // Sign the CRL using the CA private key
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(caPrivateKey);
            X509CRLHolder crlHolder = crlBuilder.build(signer);
            JcaX509CRLConverter converter = new JcaX509CRLConverter();
            crl = converter.getCRL(crlHolder);

            // Save the updated CRL to a file
            byte[] crlBytes = crl.getEncoded();
            FileOutputStream fos = new FileOutputStream("crl.crl");
            fos.write(crlBytes);
            fos.close();
        }catch (NoSuchAlgorithmException | NoSuchProviderException | CertificateException | KeyStoreException |
                IOException | OperatorCreationException | UnrecoverableKeyException | CRLException e){
            e.printStackTrace();
        }

    }

    public void reactivateSertificate(String alias){

    }

}
