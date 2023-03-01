package org.unibl.etf;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.cert.*;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.BCrypt;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.crypto.generators.BCrypt;

import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.asn1.x509.CRLReason;

import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.KeyStore;
import java.security.Security;
import java.util.*;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.util.encoders.Hex;


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

            X500Name issuer = new X500Name("CN=CARoot");
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

            keyStore.setKeyEntry("CARoot", keyPair.getPrivate(), "sigurnost".toCharArray(), new X509Certificate[] { cert });

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
            X509Certificate caCert = (X509Certificate) keyStore.getCertificate("CARoot");
            PrivateKey caPrivateKey = (PrivateKey) keyStore.getKey("CARoot", "sigurnost".toCharArray());

            X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(new X500Name(caCert.getSubjectDN().getName()), new Date());

            // Generate the CRL
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(caPrivateKey);
            X509CRLHolder crlHolder = crlBuilder.build(signer);

            // Saving the CRL to a file
            JcaX509CRLConverter converter = new JcaX509CRLConverter();
            X509CRL crl = converter.getCRL(crlHolder);
            byte[] crlBytes = crl.getEncoded();
            FileOutputStream fos = new FileOutputStream("./CERTIFICATES/" + "crl.crl");
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
            X509Certificate caCert = (X509Certificate) keyStore.getCertificate("CARoot");
            PrivateKey caPrivateKey = (PrivateKey) keyStore.getKey("CARoot", "sigurnost".toCharArray());

            // Load the existing CRL file
            FileInputStream inputStream = new FileInputStream("./CERTIFICATES/crl.crl");
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509CRL existingCRL = (X509CRL) certificateFactory.generateCRL(inputStream);
            inputStream.close();

            // Get the certificate that should be revoked
            X509Certificate suspendedCert = (X509Certificate) keyStore.getCertificate(alias);

            // Create a JcaX509CertificateHolder object from the CA certificate
            JcaX509CertificateHolder caCertHolder = new JcaX509CertificateHolder(caCert);

            // Create a new CRL builder and add the existing revoked entries
            X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(caCertHolder.getIssuer(), new Date(existingCRL.getThisUpdate().getTime()));
            Set<? extends X509CRLEntry> revokedEntries = existingCRL.getRevokedCertificates();
            if(revokedEntries!=null) {
                for (X509CRLEntry entry : revokedEntries) {
                    crlBuilder.addCRLEntry(entry.getSerialNumber(), entry.getRevocationDate(), 1);
                }
            }

            // Add the new revocation entry
            crlBuilder.addCRLEntry(suspendedCert.getSerialNumber(), new Date(), CRLReason.CERTIFICATE_HOLD);

            // Sign the CRL using the CA private key
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(caPrivateKey);
            X509CRLHolder crlHolder = crlBuilder.build(signer);
            JcaX509CRLConverter converter = new JcaX509CRLConverter();
            X509CRL updatedCRL = converter.getCRL(crlHolder);

            // Save the updated CRL to the same file
            byte[] crlBytes = updatedCRL.getEncoded();
            FileOutputStream fos = new FileOutputStream("./CERTIFICATES/crl.crl");
            fos.write(crlBytes);
            fos.close();
        }catch (NoSuchAlgorithmException | NoSuchProviderException | CertificateException | KeyStoreException |
                IOException | OperatorCreationException | UnrecoverableKeyException | CRLException e){
            e.printStackTrace();
        }

    }

    public void reactivateCertificate(String alias){

        // Add BouncyCastleProvider to Security Providers
        Security.addProvider(new BouncyCastleProvider());
        try {
            // Load the CA keystore
            KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
            FileInputStream keystoreStream = new FileInputStream("keystore.p12");
            keyStore.load(keystoreStream, "sigurnost".toCharArray());
            keystoreStream.close();

            // Get the CA certificate and private key from the keystore
            PrivateKey caPrivateKey = (PrivateKey) keyStore.getKey("CARoot", "sigurnost".toCharArray());

            // Get the certificate that should be reactivated
            X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);

            // Load the existing CRL file
            FileInputStream inputStream = new FileInputStream("./CERTIFICATES/crl.crl");
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509CRL crl = (X509CRL) certificateFactory.generateCRL(inputStream);
            inputStream.close();

            // Find revoked certificate
            Set<? extends X509CRLEntry> set = crl.getRevokedCertificates();
            Set<X509CRLEntry> updatedSet = new HashSet<>();
            for (X509CRLEntry entry : set){
                BigInteger certSerialNumber = entry.getSerialNumber();
                if (!certSerialNumber.equals(cert.getSerialNumber())) {
                    // Adding all certificates that don't have the same serial number
                    updatedSet.add(entry);
                }
            }

            // Convert the Set<? extends X509CRLEntry> to a List<X509CRLEntry>
            List<X509CRLEntry> revokedList = new ArrayList<>(updatedSet);

            // Create a new X509CRLHolder using the JcaX509v2CRLBuilder class
            JcaX509v2CRLBuilder builder = new JcaX509v2CRLBuilder(crl.getIssuerX500Principal(), new Date());
            for (X509CRLEntry entry : revokedList) {
                builder.addCRLEntry(entry.getSerialNumber(), entry.getRevocationDate(), 1);
            }
            X509CRLHolder newCrlHolder = builder.build(new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caPrivateKey));

            // Save the new CRL to a file
            FileWriter fileWriter = new FileWriter("./CERTIFICATES/" + "crl.crl");
            JcaPEMWriter pemWriter = new JcaPEMWriter(fileWriter);
            pemWriter.writeObject(newCrlHolder);
            pemWriter.flush();
            pemWriter.close();
            fileWriter.close();
        }catch (Exception e){
            e.printStackTrace();
        }

    }

    public boolean checkValidity(String path){
        // Add BouncyCastleProvider to Security Providers
        Security.addProvider(new BouncyCastleProvider());
        try {
            String caKeystorePassword = "sigurnost";

            // Load the CA certificate
            KeyStore caKeystore = KeyStore.getInstance("PKCS12", "BC");
            FileInputStream caKeystoreStream = new FileInputStream("keystore.p12");
            caKeystore.load(caKeystoreStream, caKeystorePassword.toCharArray());
            caKeystoreStream.close();
            X509Certificate caCert = (X509Certificate) caKeystore.getCertificate("CARoot");
            PublicKey caPublicKey = caCert.getPublicKey();

            // Load the user's certificate
            InputStream userCertStream = new FileInputStream(path);
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate userCert = (X509Certificate) certFactory.generateCertificate(userCertStream);
            userCertStream.close();

            // Verify the user's certificate was signed by the CA
            userCert.verify(caPublicKey);

        }catch ( CertificateException | InvalidKeyException | SignatureException e){
            System.out.println("Invalid certificate!");
            return  false;
        }catch ( IOException e){
            System.out.println("Incorrect path!");
            return false;
        }catch (NoSuchAlgorithmException | NoSuchProviderException |  KeyStoreException e){
            System.out.println("Problem with keystore!");
            return false;
        }
        System.out.println("Certificate is valid and signed by the CA.");
        return true;
    }


    public boolean checkCredentials(String username,String password, String path){
        try {
            // Load the user's certificate
            InputStream userCertStream = new FileInputStream(path);
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate userCert = (X509Certificate) certFactory.generateCertificate(userCertStream);
            userCertStream.close();

            //Export common name from the certificate and compare it with the provided username
            X500Name subjectName = new X500Name(userCert.getSubjectX500Principal().getName());
            String commonName = subjectName.getRDNs(BCStyle.CN)[0].getFirst().getValue().toString();
            if(!username.equals(commonName)){
                System.out.println("The username or password is not valid!");
                return false;
            }

            // Compare the provided password with the password that is saved while creating the account
            if(!verifyPassword(password,username)){
                System.out.println("The username or password is not valid!");
                return false;
            }
            return true;

        }catch (Exception e){
            return true;
        }
    }

    void savePassword(String userPassword, String username){
        try {
            // Generate key from password and salt using PBKDF2 with HMAC-SHA256
            PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new SHA256Digest());
            gen.init(PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(userPassword.toCharArray()), username.getBytes(), 10000);
            KeyParameter keyParam = (KeyParameter)gen.generateDerivedParameters(256);

            //Create folder
            new File("./PASSWORDS/"+username).mkdirs();

            // Save salt and encrypted password to file
            FileOutputStream fos = new FileOutputStream("./PASSWORDS/"+username+"/password.txt");
            fos.write(Hex.encode(username.getBytes()));
            fos.write(':');
            fos.write(Hex.encode(gen.getSalt()));
            fos.write(':');
            fos.write(Hex.encode(keyParam.getKey()));
            fos.close();

            System.out.println("Password encrypted and saved to file.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    boolean verifyPassword(String userPassword, String username){
        try {
            // Read salt and encrypted password from file
            FileInputStream fis = new FileInputStream("./PASSWORDS/"+username+"/password.txt");
            byte[] fileContent = fis.readAllBytes();
            fis.close();
            String[] parts = new String(fileContent, "UTF-8").split(":");
            String fileSalt = new String(Hex.decode(parts[1]));
            byte[] storedKey = Hex.decode(parts[2]);

            // Generate key from provided password and stored salt using PBKDF2 with HMAC-SHA256
            PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new SHA256Digest());
            gen.init(PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(userPassword.toCharArray()), fileSalt.getBytes(), 10000);
            KeyParameter keyParam = (KeyParameter)gen.generateDerivedParameters(256);
            byte[] generatedKey = keyParam.getKey();

            // Compare generated key with stored key
            return Arrays.equals(generatedKey, storedKey);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    boolean isSuspended(String path){
        // Get alias from path
        File file = new File(path);
        String alias = file.getName().replace(".crt", "");

        // Add BouncyCastleProvider to Security Providers
        Security.addProvider(new BouncyCastleProvider());
        try {
            // Load the CA keystore
            KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
            FileInputStream keystoreStream = new FileInputStream("keystore.p12");
            keyStore.load(keystoreStream, "sigurnost".toCharArray());
            keystoreStream.close();

            // Get the CA certificate and private key from the keystore
            PrivateKey caPrivateKey = (PrivateKey) keyStore.getKey("CARoot", "sigurnost".toCharArray());

            // Get the certificate that should be reactivated
            X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);

            // Load the existing CRL file
            FileInputStream inputStream = new FileInputStream("./CERTIFICATES/crl.crl");
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509CRL crl = (X509CRL) certificateFactory.generateCRL(inputStream);
            inputStream.close();

            // Find revoked certificate
            Set<? extends X509CRLEntry> set = crl.getRevokedCertificates();
            Set<X509CRLEntry> updatedSet = new HashSet<>();
            for (X509CRLEntry entry : set) {
                BigInteger certSerialNumber = entry.getSerialNumber();
                if (certSerialNumber.equals(cert.getSerialNumber())) {
                    // Certificate is revoked
                    return true;
                }
            }

        }catch (Exception e){
            e.printStackTrace();
        }
        return false;
    }

}
