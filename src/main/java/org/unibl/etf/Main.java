package org.unibl.etf;

import java.io.File;
import java.util.Scanner;

public class Main {
    public static Scanner scanner = new Scanner(System.in);
    public static CARoot  caRoot = new CARoot();
    public static  CertificateCreator certificateCreator = new CertificateCreator();
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
        certificateCreator.createCertificate(username,password);
        System.out.println("Your account is created!\nPlease login using your certificate in yur CERTIFICATES folder.");
        welcomeMenu();
    }

    public static void login(){
        System.out.println("Enter the path to your certificate:");
        boolean suspended = false;
        String path = scanner.nextLine();
        if(caRoot.checkValidity(path))
        {
            for(int i=0;i<=3;i++) {
                if(i==3){
                    File file = new File(path);
                    String username = file.getName().replace(".crt", "");
                    caRoot.suspendCertificate(username);
                    System.out.println("Your certificate is suspended!");
                    System.out.println("Please enter the right credentials or make a new account.");
                    suspended = true;
                    reactivate(username);
                    break;
                }
                System.out.println("Enter username:");
                String username = scanner.nextLine();
                System.out.println("Enter password:");
                String password = scanner.nextLine();
                //TODO: Check credentials
            }
            if(!suspended){
                System.out.println("Welcome to your account!");
            }

        }else{
            welcomeMenu();
        }
    }

    public static void reactivate(String alias){
        System.out.println("Enter:\n-reactivate to reactivate your suspended certificate\n-register to create a new certificate\n");
        String option = scanner.nextLine();
        if("-register".equals(option)){
            register();
        }else if("-reactivate".equals(option)){
            System.out.println("Enter username:");
            String username = scanner.nextLine();
            System.out.println("Enter password:");
            String password = scanner.nextLine();
            //TODO: Check credentials
            if(true){
                caRoot.reactivateCertificate(alias);
                System.out.println("You certificate is reactivated!");
            }else{
                System.out.println("Invalid credentials!");
            }
        }else {
            System.out.println("Invalid entry!");
            reactivate(alias);
        }
    }


    public static void main(String[] args) {
       caRoot.reactivateCertificate("gordan");
    }
}