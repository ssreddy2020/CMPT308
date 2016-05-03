import java.util.Scanner;

/**
 * File: Driver.java author: Himaja Kethiri, Sandeep Reddy Salla 
 * course: Security Algorithms and Protocols 
 * 
 * Project: AES Encryption and Decryption for 128, 192 and 256 bits  
 * Due date: May 2, 2016 
 * version: 1.0
 * 
 * This file contains the main method, it is an entry point to the
 * program. It calls AES encryption and decryption method based on 
 * the plainText or Cipher Text and the key. * 
 * 
 */

public class Driver {
	public static void main(String args[]) {
		// Giving key as the input to the aes method in AEscipher class
		String keyInput = "";
		// Giving plaintext as the input to the aes method
		String plainText = "";
		// Reading input using Scanner
		@SuppressWarnings("resource")
		Scanner input = new Scanner(System.in);
		plainText = input.nextLine().trim();
		String cipherText = "";
	//	cipherText = input.nextLine();
		if (input.hasNextLine())
			keyInput = input.nextLine().trim();
		// AESDecrypt.aes(cipherText, keyInput);	
		  AESEncrypt.aes(plainText, keyInput); 
	
		 
	}

}