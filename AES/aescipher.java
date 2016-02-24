/**
 * file: aescipher.java 
 * author: Sandeep Reddy Salla
 * course: MSCS_630L_231_16S
 * assignment: Lab 2 
 * due date: February 23, 2016 
 * version: 1.0
 * 
 * This file contains the declaration of aescipher class
 */

/**
 * advanced encryption system cipher class implements the encryption functionality for the given input
 *
 */
public class aescipher {

	public static String[][] inputKey = new String[4][4];
	public static String[][] matrixW = new String[4][44];

	public static void aesRoundKeys(String keyHex) {
		try {
			// initialize the column length of K matrix and W matrix
			int K_MATRIX_LENGTH = 4;
			int W_MATRIX_COL_LENGTH = 44;
			String[][] wNew = new String[1][4];
			int count = 0;
			// 4x4 matrix implementation
			for (int cols = 0; cols < K_MATRIX_LENGTH; cols++) {
				for (int rows = 0; rows < K_MATRIX_LENGTH; rows++) {
					int beginIndex = count;
					int endIndex = count + 2;
					inputKey[rows][cols] = keyHex.substring(beginIndex,endIndex);
					count = count + 2;
				}
			}

			for (int cols = 0; cols < K_MATRIX_LENGTH; cols++) {
				for (int rows = 0; rows < K_MATRIX_LENGTH; rows++) {
					matrixW[rows][cols] = inputKey[rows][cols];
				}
			}
			// 4x44 matrix implementation
			for (int cols = K_MATRIX_LENGTH; cols < W_MATRIX_COL_LENGTH; cols++) {
				// condition to check whether a column is a multiple of 4 or not
				if (cols % 4 != 0) {
					for (int rows = 0; rows < K_MATRIX_LENGTH; rows++) {
						matrixW[rows][cols] = calcXOR(matrixW[rows][cols - 4],matrixW[rows][cols - 1]);
					}
				} else {
					wNew[0][0] = matrixW[0][cols - 1];
					wNew[0][1] = matrixW[1][cols - 1];
					wNew[0][2] = matrixW[2][cols - 1];
					wNew[0][3] = matrixW[3][cols - 1];
					
					// shifting the position of the matrix
					wNew[0][0] = matrixW[1][cols - 1];
					wNew[0][1] = matrixW[2][cols - 1];
					wNew[0][2] = matrixW[3][cols - 1];
					wNew[0][3] = matrixW[0][cols - 1];

					for (int i = 0; i < 4; i++) {
						wNew[0][i] = aesSBox(wNew[0][i]);
					}

					String rconVal = aesRcon(cols);
					wNew[0][0] = calcXOR(wNew[0][0], rconVal);
					
					for (int rows = 0; rows < 4; rows++) {
						matrixW[rows][cols] = calcXOR(matrixW[rows][cols - 4],wNew[0][rows]);
					}
				}
			}
			print();
		} catch (Exception e) {
			System.out.println("error in aesRoundKeys" + e.getMessage());
		}
	}

	/**
	 * This method will display the eleven rounds result
	 */
	private static void print() {
		try {
			String roundKey = "";
			int counter = 0;
			for (int i = 0; i < 44; i++) {
				for (int j = 0; j < 4; j++) {
					if ((roundKey.length() == 32) || (i == 43 && j == 3)) {
						if (i == 43 && j == 3)
							roundKey += matrixW[j][i];
						System.out.println(roundKey);
						roundKey = matrixW[j][i];
					} else {
						roundKey += matrixW[j][i];
					}
				}
			}
		} catch (Exception e) {
			System.out.println("error in print" + e.getMessage());
		}
	}

	/**
	 * this method will perform XOR operation for two strings and the result is stored in the third string
	 * @param one : contains the value of string one
	 * @param two : contains the value of string two
	 * @return the result of XOR operation
	 */
	private static String calcXOR(String one, String two) {
		try {
			String three = Integer.toHexString(Integer.parseInt(one, 16)^ Integer.parseInt(two, 16));
			// condition to check the length of the result, if length is one append it with zero
			if (three.length() == 1)
				return "0" + three;
			else
				return three;
		} catch (Exception e) {
			System.out.println("error in calcXOR" + e.getMessage());
			return "0";
		}
	}

	/**
	 * Substitution box array values
	 */
	private static final String[][] S_box = {
			{ "63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67",
					"2B", "FE", "D7", "AB", "76" },
			{ "CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2",
					"AF", "9C", "A4", "72", "C0" },
			{ "B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5",
					"F1", "71", "D8", "31", "15" },
			{ "04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80",
					"E2", "EB", "27", "B2", "75" },
			{ "09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6",
					"B3", "29", "E3", "2F", "84" },
			{ "53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE",
					"39", "4A", "4C", "58", "CF" },
			{ "D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02",
					"7F", "50", "3C", "9F", "A8" },
			{ "51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA",
					"21", "10", "FF", "F3", "D2" },
			{ "CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E",
					"3D", "64", "5D", "19", "73" },
			{ "60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8",
					"14", "DE", "5E", "0B", "DB" },
			{ "E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC",
					"62", "91", "95", "E4", "79" },
			{ "E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4",
					"EA", "65", "7A", "AE", "08" },
			{ "BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74",
					"1F", "4B", "BD", "8B", "8A" },
			{ "70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57",
					"B9", "86", "C1", "1D", "9E" },
			{ "E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87",
					"E9", "CE", "55", "28", "DF" },
			{ "8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D",
					"0F", "B0", "54", "BB", "16" } };

	/**
	 * Rcon values
	 */
	private static final String[][] Rcon = {
			{ "8D", "01", "02", "04", "08", "10", "20", "40", "80", "1B", "36",
					"6C", "D8", "AB", "4D", "9A" },
			{ "2F", "5E", "BC", "63", "C6", "97", "35", "6A", "D4", "B3", "7D",
					"FA", "EF", "C5", "91", "39" },
			{ "72", "E4", "D3", "BD", "61", "C2", "9F", "25", "4A", "94", "33",
					"66", "CC", "83", "1D", "3A" },
			{ "74", "E8", "CB", "8D", "01", "02", "04", "08", "10", "20", "40",
					"80", "1B", "36", "6C", "D8" },
			{ "AB", "4D", "9A", "2F", "5E", "BC", "63", "C6", "97", "35", "6A",
					"D4", "B3", "7D", "FA", "EF" },
			{ "C5", "91", "39", "72", "E4", "D3", "BD", "61", "C2", "9F", "25",
					"4A", "94", "33", "66", "CC" },
			{ "83", "1D", "3A", "74", "E8", "CB", "8D", "01", "02", "04", "08",
					"10", "20", "40", "80", "1B" },
			{ "36", "6C", "D8", "AB", "4D", "9A", "2F", "5E", "BC", "63", "C6",
					"97", "35", "6A", "D4", "B3" },
			{ "7D", "FA", "EF", "C5", "91", "39", "72", "E4", "D3", "BD", "61",
					"C2", "9F", "25", "4A", "94" },
			{ "33", "66", "CC", "83", "1D", "3A", "74", "E8", "CB", "8D", "01",
					"02", "04", "08", "10", "20" },
			{ "40", "80", "1B", "36", "6C", "D8", "AB", "4D", "9A", "2F", "5E",
					"BC", "63", "C6", "97", "35" },
			{ "6A", "D4", "B3", "7D", "FA", "EF", "C5", "91", "39", "72", "E4",
					"D3", "BD", "61", "C2", "9F" },
			{ "25", "4A", "94", "33", "66", "CC", "83", "1D", "3A", "74", "E8",
					"CB", "8D", "01", "02", "04" },
			{ "08", "10", "20", "40", "80", "1B", "36", "6C", "D8", "AB", "4D",
					"9A", "2F", "5E", "BC", "63" },
			{ "C6", "97", "35", "6A", "D4", "B3", "7D", "FA", "EF", "C5", "91",
					"39", "72", "E4", "D3", "BD" },
			{ "61", "C2", "9F", "25", "4A", "94", "33", "66", "CC", "83", "1D",
					"3A", "74", "E8", "CB", "8D" } };

	/**
	 * splits the incoming string to get the corresponding value from S_box
	 * @param inHex : contains the value of the string
	 * @return : It will return the S_box value
	 */
	private static String aesSBox(String inHex) {
		try {
			char[] data = inHex.toCharArray();
			return S_box[Integer.parseInt(data[0] + "", 16)][Integer.parseInt(
					data[1] + "", 16)];
		} catch (Exception ex) {
			System.out.println("Exception in aesBox " + ex.getMessage());
			return "0";
		}
	}
	
	private static String aesRcon(int round) {
		return Rcon[0][round / 4];
	}
}
