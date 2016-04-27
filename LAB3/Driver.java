/**
 * file: Driver.java
 * author: Sandeep Reddy Salla
 * course: MSCS_630L_231_16S 
 * assignment: Lab 3
 * due date: March 31, 2016
 * version: 1.1
 * 
 * This file contains the declaration of driver class
 */

import java.util.Scanner;

/**
 * This class is used to take the input from the scanner and calls the advanced
 * encryption round key method by providing the input
 */
public class Driver {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		// Scanner is used to read input from the console
		Scanner sc = new Scanner(System.in);
		String plainText = sc.nextLine();
		String key_Hex = sc.nextLine();
		// condition to check whether the input length is 32 or not
		if (plainText.length() == 32 && key_Hex.length() == 32) {
			AEScipher.aes(plainText, key_Hex);
			// closes the scanner
			sc.close();
		} else {
			System.out.println("Plaintext/keyhex length is not 32");
		}
	}
}
