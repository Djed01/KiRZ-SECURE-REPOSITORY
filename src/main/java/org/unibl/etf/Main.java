package org.unibl.etf;

import java.io.File;
import java.util.Scanner;

public class Main {
    public static Scanner scanner = new Scanner(System.in);
    public static CARoot  caRoot = new CARoot();
    public static  CertificateCreator certificateCreator = new CertificateCreator();
    public static User user = new User();
    public static void  welcomeMenu(){
        System.out.println("Enter '-register' for registration or -login for login to sign in\n");
        String option = scanner.nextLine();
        if("-login".equals(option)){
            login();
        }else if("-register".equals(option)){
            register();
        }else{
            System.out.println("Invalid entry!");
            welcomeMenu();
        }
    }

    public static void register(){
        System.out.println("Enter username:");
        String username = scanner.nextLine();
        System.out.println("Enter password:");
        String password = scanner.nextLine();
        certificateCreator.createCertificate(username);
        caRoot.savePassword(password,username);
        //Create folder for user
        new File("./REPOSITORY/"+username).mkdirs();
        new File("./DOWNLOADS/"+username).mkdirs();
        new File("./HASHES/"+username).mkdirs();
        for(int i=1;i<= User.maxParts;i++){
            new File("./REPOSITORY/"+username+"/dir"+i).mkdirs();
        }
        System.out.println("Your account is created!\nPlease login using your certificate in yur CERTIFICATES folder.");
        welcomeMenu();
    }

    public static void login(){
        System.out.println("Enter the path to your certificate:");
        boolean suspended = false;
        String path = scanner.nextLine();
        String username = null;
        // Check if the certificate is suspended
        if(!caRoot.isSuspended(path)) {
            if (caRoot.checkValidity(path)) {
                for (int i = 0; i <= 3; i++) {
                    if (i == 3) {
                        File file = new File(path);
                        username = file.getName().replace(".crt", "");
                        caRoot.suspendCertificate(username);
                        System.out.println("Your certificate is suspended!");
                        System.out.println("Please enter the right credentials or make a new account.");
                        suspended = true;
                        reactivate(username, path);
                        break;
                    }
                    System.out.println("Enter username:");
                    username = scanner.nextLine();
                    System.out.println("Enter password:");
                    String password = scanner.nextLine();
                    //Check credentials
                    if (caRoot.checkCredentials(username, password, path)) {
                        break;
                    }
                }
                if (!suspended) {
                    System.out.println("Welcome to your repository!");
                    repositoryMenu(username);
                }

            }else{
                welcomeMenu();
            }
        }else{
            System.out.println("Your certificate is suspended!");
            welcomeMenu();
        }
    }

    public static void reactivate(String alias, String path){
        System.out.println("Enter:\n-reactivate to reactivate your suspended certificate\n-register to create a new certificate\n");
        String option = scanner.nextLine();
        if("-register".equals(option)){
            register();
        }else if("-reactivate".equals(option)){
            System.out.println("Enter username:");
            String username = scanner.nextLine();
            System.out.println("Enter password:");
            String password = scanner.nextLine();
            // Check credentials
            if(caRoot.checkCredentials(username,password,path)){
                caRoot.reactivateCertificate(alias);
                System.out.println("You certificate is reactivated!");
                welcomeMenu();
            }else{
                System.out.println("Invalid credentials!");
            }
        }else {
            System.out.println("Invalid entry!");
            reactivate(alias, path);
        }
    }

    public static void repositoryMenu(String username){
        System.out.println("Enter a command:");
        System.out.println("-list --> To show your list of files");
        System.out.println("-upload --> To upload a file to your repository");
        System.out.println("-download --> To download a file from your repository");
        System.out.println("-exit --> To exit the application\n");
        String option = scanner.nextLine();
        if("-list".equals(option)){
            list(username);
            repositoryMenu(username);
        }else if("-upload".equals(option)){
            user.upload(username);
            repositoryMenu(username);
        }else if("-download".equals(option)){
            System.out.println("Enter the name of the file to download:");
            String fileName = scanner.nextLine();
            user.download(username,fileName);
            repositoryMenu(username);
        }else if("-exit".equals(option)){

        }
        else{
            System.out.println("Invalid command!\n\n");
            repositoryMenu(username);
        }
    }

    public static void list(String username){
        File directory = new File("./REPOSITORY/"+username+"/dir1");
        File[] files = directory.listFiles();
        for (File file : files) {
            if (file.isFile()) {
                System.out.println(file.getName().substring(0, file.getName().length() - 2));
            }
        }
        System.out.println("");
    }




    public static void main(String[] args) {
       welcomeMenu();
//       user.upload("jovan");
//         user.download("jovan","test.txt");
//        repositoryMenu("jovan");

    }
}