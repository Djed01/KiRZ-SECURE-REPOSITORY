package org.unibl.etf;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
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


    public void upload(String username){
        Security.addProvider(new BouncyCastleProvider()); // add Bouncy Castle as security provider
        System.out.println("Enter the path of the file that should be uploaded:");
        String inputFile = scanner.nextLine();

        int numParts = (int) Math.floor(Math.random() * (maxParts - minParts + 1) + minParts); // choose between 4 and 7 parts randomly

        int bufferSize = 1024; // buffer size in bytes
        String keyFile = "./KEYS/AESkey.bin"; // path to file containing AES key
        byte[] keyBytes = null;

        try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(inputFile))) {
            long fileSize = new File(inputFile).length(); // get size of input file
            long bytesPerPart = fileSize / numParts; // calculate number of bytes per output file
            long remainingBytes = fileSize; // remaining bytes to read
            int numBytesWritten = 0;

            // read AES key from file
            try (BufferedInputStream keyStream = new BufferedInputStream(new FileInputStream(keyFile))) {
                keyBytes = new byte[keyStream.available()];
                keyStream.read(keyBytes);
            } catch (IOException e) {
                e.printStackTrace();
            }
            // create AES key object
            SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

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

            for (int i = 1; i <= numParts; i++) {
                String partFileName = inputFile + "." + i;
                try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream("./REPOSITORY/"+username+"/dir"+i+"/"+partFileName))) {
                    long bytesToRead;
                    if(i == numParts){
                         bytesToRead = Math.min(bytesPerPart + (fileSize % numParts), remainingBytes); // calculate number of bytes to read with leftover
                    }else {
                         bytesToRead = Math.min(bytesPerPart, remainingBytes); // calculate number of bytes to read
                    }
                    remainingBytes -= bytesToRead; // update remaining bytes
                    byte[] buffer = new byte[bufferSize];
                    int bytesRead = 0;
                    int totalBytesWritten = 0;

                    // create AES cipher object
                    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
                    cipher.init(Cipher.ENCRYPT_MODE, key);

                    while (bytesToRead > 0 && (bytesRead = bis.read(buffer, 0, (int)Math.min(buffer.length, bytesToRead))) != -1) {
                        byte[] encrypted = cipher.update(buffer, 0, bytesRead); // encrypt buffer
                        bos.write(encrypted); // write encrypted data to output file
                        totalBytesWritten += encrypted.length;
                        bytesToRead -= bytesRead; // update bytes left to read
                    }
                    // Save the hash to the file system
                    MessageDigest digest = MessageDigest.getInstance("SHA-256");
                    byte[] hashBytes = digest.digest(buffer);
                    // Sign the hashes
                    signature.update(hashBytes);
                    byte[] digitalSignature = signature.sign();

                    FileOutputStream signatureFile = new FileOutputStream("./HASHES/"+username+"/"+partFileName+".sig");
                    signatureFile.write(digitalSignature);
                    signatureFile.close();

                    // write any remaining encrypted data to output file
                    byte[] finalEncrypted = cipher.doFinal();
                    bos.write(finalEncrypted);
                    totalBytesWritten += finalEncrypted.length;
                    numBytesWritten += totalBytesWritten;
                  //  System.out.println("Part " + (i+1) + " written: " + totalBytesWritten + " bytes");
                } catch (IOException | BadPaddingException | IllegalBlockSizeException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException e) {
                    e.printStackTrace();
                }
            }

          //  System.out.println("Total bytes written: " + numBytesWritten);
        } catch (Exception e) {
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
                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
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
