/**
 * file: AEScipher.java 
 * author: Sandeep Reddy Salla
 * course: MSCS_630L_231_16S
 * assignment: Lab 3 
 * due date: March 31, 2016 
 * version: 1.1
 * 
 * This file contains the declaration of aescipher class
 */

/**
 * advanced encryption system cipher class implements the encryption
 * functionality for the given input
 *
 */
public class AEScipher {

	public static String[][] inputKey = new String[4][4];
	public static String[][] matrixW = new String[4][44];
	// this matrix is used for aesMixColumn
	public static String[][] GaloisMatrix = { { "02", "03", "01", "01" },
			{ "01", "02", "03", "01" }, { "01", "01", "02", "03" },
			{ "03", "01", "01", "02" } };

	public static int[][] mc2 = {
			{ 0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x14,
					0x16, 0x18, 0x1a, 0x1c, 0x1e },
			{ 0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e, 0x30, 0x32, 0x34,
					0x36, 0x38, 0x3a, 0x3c, 0x3e },
			{ 0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e, 0x50, 0x52, 0x54,
					0x56, 0x58, 0x5a, 0x5c, 0x5e },
			{ 0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e, 0x70, 0x72, 0x74,
					0x76, 0x78, 0x7a, 0x7c, 0x7e },
			{ 0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e, 0x90, 0x92, 0x94,
					0x96, 0x98, 0x9a, 0x9c, 0x9e },
			{ 0xa0, 0xa2, 0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae, 0xb0, 0xb2, 0xb4,
					0xb6, 0xb8, 0xba, 0xbc, 0xbe },
			{ 0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce, 0xd0, 0xd2, 0xd4,
					0xd6, 0xd8, 0xda, 0xdc, 0xde },
			{ 0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee, 0xf0, 0xf2, 0xf4,
					0xf6, 0xf8, 0xfa, 0xfc, 0xfe },
			{ 0x1b, 0x19, 0x1f, 0x1d, 0x13, 0x11, 0x17, 0x15, 0x0b, 0x09, 0x0f,
					0x0d, 0x03, 0x01, 0x07, 0x05 },
			{ 0x3b, 0x39, 0x3f, 0x3d, 0x33, 0x31, 0x37, 0x35, 0x2b, 0x29, 0x2f,
					0x2d, 0x23, 0x21, 0x27, 0x25 },
			{ 0x5b, 0x59, 0x5f, 0x5d, 0x53, 0x51, 0x57, 0x55, 0x4b, 0x49, 0x4f,
					0x4d, 0x43, 0x41, 0x47, 0x45 },
			{ 0x7b, 0x79, 0x7f, 0x7d, 0x73, 0x71, 0x77, 0x75, 0x6b, 0x69, 0x6f,
					0x6d, 0x63, 0x61, 0x67, 0x65 },
			{ 0x9b, 0x99, 0x9f, 0x9d, 0x93, 0x91, 0x97, 0x95, 0x8b, 0x89, 0x8f,
					0x8d, 0x83, 0x81, 0x87, 0x85 },
			{ 0xbb, 0xb9, 0xbf, 0xbd, 0xb3, 0xb1, 0xb7, 0xb5, 0xab, 0xa9, 0xaf,
					0xad, 0xa3, 0xa1, 0xa7, 0xa5 },
			{ 0xdb, 0xd9, 0xdf, 0xdd, 0xd3, 0xd1, 0xd7, 0xd5, 0xcb, 0xc9, 0xcf,
					0xcd, 0xc3, 0xc1, 0xc7, 0xc5 },
			{ 0xfb, 0xf9, 0xff, 0xfd, 0xf3, 0xf1, 0xf7, 0xf5, 0xeb, 0xe9, 0xef,
					0xed, 0xe3, 0xe1, 0xe7, 0xe5 } };

	public static int[][] mc3 = {
			{ 0x00, 0x03, 0x06, 0x05, 0x0c, 0x0f, 0x0a, 0x09, 0x18, 0x1b, 0x1e,
					0x1d, 0x14, 0x17, 0x12, 0x11 },
			{ 0x30, 0x33, 0x36, 0x35, 0x3c, 0x3f, 0x3a, 0x39, 0x28, 0x2b, 0x2e,
					0x2d, 0x24, 0x27, 0x22, 0x21 },
			{ 0x60, 0x63, 0x66, 0x65, 0x6c, 0x6f, 0x6a, 0x69, 0x78, 0x7b, 0x7e,
					0x7d, 0x74, 0x77, 0x72, 0x71 },
			{ 0x50, 0x53, 0x56, 0x55, 0x5c, 0x5f, 0x5a, 0x59, 0x48, 0x4b, 0x4e,
					0x4d, 0x44, 0x47, 0x42, 0x41 },
			{ 0xc0, 0xc3, 0xc6, 0xc5, 0xcc, 0xcf, 0xca, 0xc9, 0xd8, 0xdb, 0xde,
					0xdd, 0xd4, 0xd7, 0xd2, 0xd1 },
			{ 0xf0, 0xf3, 0xf6, 0xf5, 0xfc, 0xff, 0xfa, 0xf9, 0xe8, 0xeb, 0xee,
					0xed, 0xe4, 0xe7, 0xe2, 0xe1 },
			{ 0xa0, 0xa3, 0xa6, 0xa5, 0xac, 0xaf, 0xaa, 0xa9, 0xb8, 0xbb, 0xbe,
					0xbd, 0xb4, 0xb7, 0xb2, 0xb1 },
			{ 0x90, 0x93, 0x96, 0x95, 0x9c, 0x9f, 0x9a, 0x99, 0x88, 0x8b, 0x8e,
					0x8d, 0x84, 0x87, 0x82, 0x81 },
			{ 0x9b, 0x98, 0x9d, 0x9e, 0x97, 0x94, 0x91, 0x92, 0x83, 0x80, 0x85,
					0x86, 0x8f, 0x8c, 0x89, 0x8a },
			{ 0xab, 0xa8, 0xad, 0xae, 0xa7, 0xa4, 0xa1, 0xa2, 0xb3, 0xb0, 0xb5,
					0xb6, 0xbf, 0xbc, 0xb9, 0xba },
			{ 0xfb, 0xf8, 0xfd, 0xfe, 0xf7, 0xf4, 0xf1, 0xf2, 0xe3, 0xe0, 0xe5,
					0xe6, 0xef, 0xec, 0xe9, 0xea },
			{ 0xcb, 0xc8, 0xcd, 0xce, 0xc7, 0xc4, 0xc1, 0xc2, 0xd3, 0xd0, 0xd5,
					0xd6, 0xdf, 0xdc, 0xd9, 0xda },
			{ 0x5b, 0x58, 0x5d, 0x5e, 0x57, 0x54, 0x51, 0x52, 0x43, 0x40, 0x45,
					0x46, 0x4f, 0x4c, 0x49, 0x4a },
			{ 0x6b, 0x68, 0x6d, 0x6e, 0x67, 0x64, 0x61, 0x62, 0x73, 0x70, 0x75,
					0x76, 0x7f, 0x7c, 0x79, 0x7a },
			{ 0x3b, 0x38, 0x3d, 0x3e, 0x37, 0x34, 0x31, 0x32, 0x23, 0x20, 0x25,
					0x26, 0x2f, 0x2c, 0x29, 0x2a },
			{ 0x0b, 0x08, 0x0d, 0x0e, 0x07, 0x04, 0x01, 0x02, 0x13, 0x10, 0x15,
					0x16, 0x1f, 0x1c, 0x19, 0x1a } };

	public static String[][] aesRoundKeys(String keyHex) {
		try {
			// initialize the column length of K matrix and W matrix
			int K_MATRIX_LENGTH = 4;
			int W_MATRIX_COL_LENGTH = 44;
			String[][] wNew = new String[1][4];
			int count = 0;
			// 4x4 matrix implementation
			for (int cols = 0; cols < 4; cols++) {
				for (int rows = 0; rows < 4; rows++) {
					int beginIndex = count;
					int endIndex = count + 2;
					inputKey[rows][cols] = keyHex.substring(beginIndex,
							endIndex);
					count = count + 2;
				}
			}

			for (int cols = 0; cols < 4; cols++) {
				for (int rows = 0; rows < 4; rows++) {
					matrixW[rows][cols] = inputKey[rows][cols];
				}
			}
			// 4x44 matrix implementation
			for (int cols = 4; cols < 44; cols++) {
				// condition to check whether a column is a multiple of 4 or not
				if (cols % 4 != 0) {
					for (int rows = 0; rows < 4; rows++) {
						matrixW[rows][cols] = calcXOR(matrixW[rows][cols - 4],
								matrixW[rows][cols - 1]);
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
						matrixW[rows][cols] = calcXOR(matrixW[rows][cols - 4],
								wNew[0][rows]);
					}
				}
			}
			String[][] result = print();
			return result;

		} catch (Exception e) {
			System.out.println("error in aesRoundKeys" + e.getMessage());
		}
		return null;
	}

	/**
	 * This method will display the eleven rounds result
	 */
	private static String[][] print() {
		try {
			String roundKey = "";
			// int counter = 0;
			for (int i = 0; i < 44; i++) {
				for (int j = 0; j < 4; j++) {
					if ((roundKey.length() == 32) || (i == 43 && j == 3)) {
						if (i == 43 && j == 3)
							roundKey += matrixW[j][i];
						System.out.println(roundKey);
						roundKey = matrixW[j][i].toUpperCase();
					} else {
						roundKey += matrixW[j][i].toUpperCase();
					}
				}
			}
		} catch (Exception e) {
			System.out.println("error in print" + e.getMessage());
		}
		return null;
	}

	/**
	 * this method will perform XOR operation for two strings and the result is
	 * stored in the third string *
	 * 
	 * @param one
	 *            : contains the value of string one
	 * @param two
	 *            : contains the value of string two
	 * @return the result of XOR operation
	 */
	private static String calcXOR(String one, String two) {
		try {
			String three = Integer.toHexString(Integer.parseInt(one, 16)
					^ Integer.parseInt(two, 16));
			// condition to check the length of the result, if length is one
			// append it with zero
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
	 * 
	 * @param inHex
	 *            : contains the value of the string
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

	/**
	 * this method is used to xor the two 4x4 matrices
	 * 
	 * @param sHex
	 *            elements of the first matrix
	 * @param keyHex
	 *            elements of the second matrix
	 * @return the output of the xored matrix
	 */
	private static String[][] aesStateXOR(String[][] sHex, String[][] keyHex) {
		// test case
		/*
		 * String[][] sHex1 = { { "54", "4F", "4E", "20" }, { "77", "6E", "69",
		 * "54" }, { "6F", "65", "6E", "77" }, { "20", "20", "65", "6F" } };
		 * String[][] keyHex1 = { { "54", "73", "20", "67" }, { "68", "20",
		 * "4B", "20" }, { "61", "6D", "75", "46" }, { "74", "79", "6E", "75" }
		 * };
		 */

		String[][] outStateHex = new String[4][4];
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				// calling calcXOR method to perform xor operation
				outStateHex[i][j] = calcXOR(sHex[i][j], keyHex[i][j]);
			}
		}
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				// It will display the output in the console
				System.out.print(outStateHex[i][j] + "\t");
			}
			System.out.println();
		}
		return outStateHex;
	}

	/**
	 * this method is used to substitute the elements of a aesState 4x4 matrix
	 * 
	 * @param inStateHex
	 *            input will be elements of 4 x 4 matrix
	 * @return the matrix with substituted elements
	 */
	private static String[][] aesNibbleSub(String[][] inStateHex) {
		String[][] outStateHex = new String[4][4];
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				// calling aesSBox method to substitute the elements of the
				// matrix
				outStateHex[i][j] = aesSBox(outStateHex[i][j]);
			}
		}

		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				// It will display the output in the console
				System.out.print(outStateHex[i][j] + "\t");
			}
			System.out.println();
		}

		return outStateHex;
	}

	/**
	 * this method is used to shift the elements of the row
	 * 
	 * @param inStateHex
	 *            input will be elements of 4 x 4 matrix
	 * @return it will return the shift row elements of the matrix
	 */
	private static String[][] aesShiftRow(String[][] inStateHex) {
		String[][] outShiftRow = new String[4][4];
		int count = 0;
		for (int x = 0; x <= 3; x++) {
			for (int y = 0; y <= 3; y++) {
				// It will shift the elements of the row
				outShiftRow[x][y] = inStateHex[x][(y + count) % 4];
			}
			count++;
		}
		for (int x = 0; x < 4; x++) {
			for (int y = 0; y < 4; y++) {
				// It will display the output in the console
				System.out.print(outShiftRow[x][y] + "\t");
			}
			System.out.println();
		}
		return outShiftRow;
	}

	/**
	 * this method is used to perform 10 round key operation
	 * 
	 * @param pTextHex
	 *            : it contains the plain text
	 * @param keyHex
	 *            : it contains the key
	 * @return : it returns the round key values
	 */
	protected static String[][] aes(String pTextHex, String keyHex) {
		String[][] keys = aesRoundKeys(keyHex);
		String[][] cTextHex = aesRoundKeys(pTextHex);
		String[][] res = aesStateXOR(keys, cTextHex);

		for (int i = 1; i <= 10; i++) {
			res = aesNibbleSub(res);
			res = aesShiftRow(res);
			// res = aesMixColumn(res);
			// res = aesStateXOR(res, keys[i]);
		}
		return res;
	}
}
