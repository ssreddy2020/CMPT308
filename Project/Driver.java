import java.util.Scanner;

/**
 * File: Driver.java 
 * author: Himaja Kethiri, Sandeep Reddy Salla 
 * course:Security Algorithms and Protocols
 * Project: AES Encryption and Decryption for 128, 192 and 256 bits Due date:
 * May 2, 2016 version: 1.0
 * 
 * This file contains the main method, it is an entry point to the program. It
 * calls AES encryption and decryption method based on the plainText or Cipher
 * Text and the key.
 * 
 */

public class Driver {
    protected static Scanner input = new Scanner(System.in);

    public static void main(String args[]) {
        boolean end = false;
        // Giving key as the input to the aes()
        String keyInput = "";
        // Giving plaintext as the input to the aes method in AESEncrypt.java
        String plainText = "";
        // Giving ciphertext as the input to the aes method in AESDecrypt.java
        String cipherText = "";
        String text = "";
        // Dispalying the options
        System.out.println("Enter e for Encryption");
        System.out.println("Enter d for Decryption");
        // Reading input using Scanner
        Scanner input = new Scanner(System.in);
        text = input.nextLine();
        if (text.equals("e")) {
            System.out.println("Encryption option is selected");
            plainText = input.nextLine().trim();
            System.out.println("PlainText:" + plainText);
            keyInput = input.nextLine().trim();
            System.out.println("Key:" + keyInput);
            AESEncrypt.aes(plainText, keyInput);
        } else if (text.equals("d")) {
            System.out.println("Decryption option is selected");
            cipherText = input.nextLine().trim();
            System.out.println("CipherText:" + cipherText);
            keyInput = input.nextLine().trim();
            System.out.println("Key:" + keyInput);
            AESDecrypt.aes(cipherText, keyInput);
        } else {
            System.out.println("please select valid option");
        }
    }
}