/**
 * file: driver.java
 * author: Sandeep Reddy Salla
 * course: MSCS_630L_231_16S 
 * assignment: Lab 2
 * due date: February 23, 2016
 * version: 1.0
 * 
 * This file contains the declaration of driver class
 */

import java.util.Scanner;

/**
 * This class is used to take the input from the scanner and calls the advanced
 * encryption round key method by providing the input
 */
public class driver {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		// Scanner is used to read input from the console
		Scanner sc = new Scanner(System.in);
		System.out.println("Enter the key:");
		String input = sc.nextLine();
		// condition to check whether the input length is 32 or not
		if (input.length() == 32) {
			aescipher.aesRoundKeys(input);
			// closes the scanner
			sc.close();
		} else {
			System.out.println("Input length is not 32");
		}
	}
}
