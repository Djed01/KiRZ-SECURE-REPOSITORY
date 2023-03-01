package org.unibl.etf;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Scanner;

public class User {
    private  static final int minParts = 4;
    public static final int maxParts = 7;

    Scanner scanner = new Scanner(System.in);


    public void generateSymmetricKey(){
        // Add BouncyCastleProvider to Security Providers
        Security.addProvider(new BouncyCastleProvider());
        try {
            // Initialize the key generator with Bouncy Castle provider
            KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
            SecureRandom random = new SecureRandom();
            keyGen.init(128, random);
            // Generate the AES key
            SecretKey aesKey = keyGen.generateKey();
            // Save the AES key to a file
            byte[] keyBytes = aesKey.getEncoded();
            FileOutputStream keyOut = new FileOutputStream("./KEYS/AESkey.bin");
            keyOut.write(keyBytes);
            keyOut.close();
            System.out.println("AES key saved to AESkey.bin");
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public void upload(String username) {
        System.out.println("Enter the path of the file that should be uploaded:");
        String filePath = scanner.nextLine();

        // Add Bouncy Castle provider
        Security.addProvider(new BouncyCastleProvider());

        try {
            // Load the CA keystore
            KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
            FileInputStream keystoreStream = new FileInputStream("keystore.p12");
            keyStore.load(keystoreStream, "sigurnost".toCharArray());
            keystoreStream.close();

            // Get the users certificate and private key from the keystore
            X509Certificate userCert = (X509Certificate) keyStore.getCertificate(username);
            PrivateKey userPrivateKey = (PrivateKey) keyStore.getKey(username, "sigurnost".toCharArray());

            Signature signature = Signature.getInstance("SHA256withRSA", "BC");
            signature.initSign(userPrivateKey);

            // Load the AES 128 key from the file system
            byte[] keyBytes = Files.readAllBytes(Paths.get("./KEYS/AESkey.bin"));
            SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

            File inputFile = new File(filePath);
            FileInputStream inputStream = new FileInputStream(inputFile);
            long fileSize = inputFile.length();
            int numParts = (int) Math.floor(Math.random() * (maxParts - minParts + 1) + minParts); // choose between 4 and 7 parts randomly
            long partSize = fileSize / numParts;


            for (int i = 1; i <= numParts; i++) {
                String partFileName = inputFile.getName() + "." + i;
                FileOutputStream outputStream;

                long startByte = i * partSize;
                long endByte = startByte + partSize - 1;
                if (i == numParts) {  //TODO : numParts-1
                    endByte = fileSize - 1;
                }

                inputStream.getChannel().position(startByte);
                byte[] buffer = new byte[1024];
                long bytesRead = 0;
                while (bytesRead < partSize) {
                    int bytes = inputStream.read(buffer);
                    if (bytes <= 0) {
                        break;
                    }
                    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "BC");
                    cipher.init(Cipher.ENCRYPT_MODE, key);

                    byte[] encryptedData = cipher.doFinal(buffer);

                    // Save the hash to the file system
                    MessageDigest digest = MessageDigest.getInstance("SHA-256");
                    byte[] hashBytes = digest.digest(buffer);

                    // Sign the hashes
                    signature.update(hashBytes);
                    byte[] digitalSignature = signature.sign();

                    FileOutputStream signatureFile = new FileOutputStream("./HASHES/"+username+"/"+partFileName+".sig");
                    signatureFile.write(digitalSignature);
                    signatureFile.close();

                    // Write the encrypted data to a new file
                    outputStream= new FileOutputStream("./REPOSITORY/"+username+"/dir"+i+"/"+partFileName);
                    outputStream.write(encryptedData, 0, bytes);
                    bytesRead += bytes;
                    outputStream.close();
                }


            }
            inputStream.close();
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public void download(String username, String fileName) {
        // Add Bouncy Castle provider
        Security.addProvider(new BouncyCastleProvider());
        try {
            // Load the AES 128 key from the file system
            byte[] keyBytes = Files.readAllBytes(Paths.get("./KEYS/AESkey.bin"));
            SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

            // Create a new file to store the decrypted data
            File outputFile = new File("./DOWNLOADS/"+username+"/"+fileName);
            FileOutputStream outputStream = new FileOutputStream(outputFile);

            // Iterate over the parts of the file
            int i = 1;
            while (true) {
                String partFileName = fileName + "." + i;
                File inputFile = new File("./REPOSITORY/"+username+"/dir"+i+"/"+partFileName);
                if (!inputFile.exists()) {
                    break;
                }

                // Read the encrypted data from the input file
                byte[] encryptedData = Files.readAllBytes(inputFile.toPath());

                // Decrypt the data using AES decryption with the loaded AES key
                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "BC");
                cipher.init(Cipher.DECRYPT_MODE, key);
                byte[] decryptedData = cipher.doFinal(encryptedData);

                // Write the decrypted data to the output file
                outputStream.write(decryptedData);

                i++;
            }

            outputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
