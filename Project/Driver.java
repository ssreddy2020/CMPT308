import java.io.FileNotFoundException;
import java.util.Scanner;

/**
 * File: Driver.java author: Himaja Kethiri, Sandeep Reddy Salla 
 * course:Security Algorithms and Protocols 
 * Project: AES Encryption and Decryption for 128, 192 and 256 bits
 * Due date: May 2, 2016 version: 1.0
 * 
 * This file contains the main method, it is an entry point to the program. It
 * calls AES encryption and decryption method based on the plainText or Cipher
 * Text and the key.
 * 
 */

public class Driver {
	public static void main(String args[]) throws FileNotFoundException {

		Scanner getInput = new Scanner(System.in);
		String plain = getInput.nextLine();
		String key = "";
		String paddedMessage = "";
		String[] array = new String[plain.length() / 4];
		if (getInput.hasNext())
			key = getInput.nextLine();
		System.out.println("--Input--");
		System.out.println("Plain Text:" + plain);
		System.out.println("key:" + key);

		if (plain.length() != 32) {
			if (plain.length() > 32) {
				int x = 0;
				String temp = "";
				for (int j = 0; j < plain.length(); j++) {
					if (temp.length() < 32) {
						temp += plain.charAt(j);
					} else {
						array[x] = temp;
						temp = "";
						temp += plain.charAt(j);
						x++;
					}
				}
				array[x] = temp;
			}
			if (plain.length() < 32) {
				array[0] = messagePadding(plain);
			}
		} else if (plain.length() == 32) {
			array[0] = plain;
		} else {
			System.out.println("Invalid PlainText entered");
		}
		System.out.println("--Output--");
		String cipher = AESEncrypt.aes(array[0], key);
		System.out.println("");
		String decryptedText = AESDecrypt.aes(cipher, key);
		getInput.close();
		
		if (plain.length() != 32) {
			for (int k = 0; k < decryptedText.length(); k++) {
				if (k == decryptedText.length() - 1) {
					int counter = 0;
					paddedMessage = decryptedText.toString();
					String paddedVal = paddedMessage.substring(30, 32);
					for (int i = 0; i < 16; i++) {
						String val = paddedMessage.charAt(i * 2) + ""
								+ paddedMessage.charAt(i * 2 + 1);
						if (paddedVal.equals(val)) {
							counter++;
						}
					}
					if (counter == Integer.parseInt(paddedVal)) {
						paddedMessage = paddedMessage.replace(paddedVal, "");
					}
				}
			}
			System.out.print("Plain  Text:");
			System.out.print(paddedMessage.toUpperCase());
		} else {
			System.out.println("Plain  Text:" + decryptedText.toUpperCase());
		}
	}

	public static String messagePadding(String text) {
		StringBuffer str = new StringBuffer(text);
		int sizeOfpadeedvalue = 32 - text.length();
		for (int i = 0; i < sizeOfpadeedvalue / 2; i++) {
			if (sizeOfpadeedvalue > 9) {
				str = str.append(sizeOfpadeedvalue);
			} else {
				str = str.append("0").append(sizeOfpadeedvalue / 2);
			}
		}
		return str.toString();
	}
}