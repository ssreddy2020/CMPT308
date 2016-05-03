import java.util.HashMap;

/**
 * file: AEScipher.java author: Himaja Kethiri, Sandeep Reddy Salla 
 * course: Security Algorithms and Protocols 
 * 
 * Project: AES Encryption and Decryption for 128, 192 and 256 bits  
 * Due date: May 2, 2016 
 * version: 1.0
 * 
 * This file contains the methods to encrypt the plain text using the key
 * of 128, 192 and 256 bits.
 * 
 */
public class AESEncrypt {
	// S_Box is a substitute box which is an array
	public static final String[][] S_Box = {
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
	// Rcon is a round constant look up table
	public static final String[][] Round_Keys = {
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
	// Multiplication with 2 look-up table
	public static int[] mc2 = { 0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e,
			0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e, 0x20, 0x22, 0x24,
			0x26, 0x28, 0x2a, 0x2c, 0x2e, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3a,
			0x3c, 0x3e, 0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e, 0x50,
			0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e, 0x60, 0x62, 0x64, 0x66,
			0x68, 0x6a, 0x6c, 0x6e, 0x70, 0x72, 0x74, 0x76, 0x78, 0x7a, 0x7c,
			0x7e, 0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e, 0x90, 0x92,
			0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e, 0xa0, 0xa2, 0xa4, 0xa6, 0xa8,
			0xaa, 0xac, 0xae, 0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe,
			0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce, 0xd0, 0xd2, 0xd4,
			0xd6, 0xd8, 0xda, 0xdc, 0xde, 0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea,
			0xec, 0xee, 0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe, 0x1b,
			0x19, 0x1f, 0x1d, 0x13, 0x11, 0x17, 0x15, 0x0b, 0x09, 0x0f, 0x0d,
			0x03, 0x01, 0x07, 0x05, 0x3b, 0x39, 0x3f, 0x3d, 0x33, 0x31, 0x37,
			0x35, 0x2b, 0x29, 0x2f, 0x2d, 0x23, 0x21, 0x27, 0x25, 0x5b, 0x59,
			0x5f, 0x5d, 0x53, 0x51, 0x57, 0x55, 0x4b, 0x49, 0x4f, 0x4d, 0x43,
			0x41, 0x47, 0x45, 0x7b, 0x79, 0x7f, 0x7d, 0x73, 0x71, 0x77, 0x75,
			0x6b, 0x69, 0x6f, 0x6d, 0x63, 0x61, 0x67, 0x65, 0x9b, 0x99, 0x9f,
			0x9d, 0x93, 0x91, 0x97, 0x95, 0x8b, 0x89, 0x8f, 0x8d, 0x83, 0x81,
			0x87, 0x85, 0xbb, 0xb9, 0xbf, 0xbd, 0xb3, 0xb1, 0xb7, 0xb5, 0xab,
			0xa9, 0xaf, 0xad, 0xa3, 0xa1, 0xa7, 0xa5, 0xdb, 0xd9, 0xdf, 0xdd,
			0xd3, 0xd1, 0xd7, 0xd5, 0xcb, 0xc9, 0xcf, 0xcd, 0xc3, 0xc1, 0xc7,
			0xc5, 0xfb, 0xf9, 0xff, 0xfd, 0xf3, 0xf1, 0xf7, 0xf5, 0xeb, 0xe9,
			0xef, 0xed, 0xe3, 0xe1, 0xe7, 0xe5 };
	// Creating mul2 hashmap with integer values
	public static HashMap<Integer, Integer> mul2 = new HashMap<Integer, Integer>();
	// Creating mul3 hashmap with integer values
	public static HashMap<Integer, Integer> mul3 = new HashMap<Integer, Integer>();
	// Multiplication with 3 look-up table
	public static int[] mc3 = { 0x00, 0x03, 0x06, 0x05, 0x0c, 0x0f, 0x0a, 0x09,
			0x18, 0x1b, 0x1e, 0x1d, 0x14, 0x17, 0x12, 0x11, 0x30, 0x33, 0x36,
			0x35, 0x3c, 0x3f, 0x3a, 0x39, 0x28, 0x2b, 0x2e, 0x2d, 0x24, 0x27,
			0x22, 0x21, 0x60, 0x63, 0x66, 0x65, 0x6c, 0x6f, 0x6a, 0x69, 0x78,
			0x7b, 0x7e, 0x7d, 0x74, 0x77, 0x72, 0x71, 0x50, 0x53, 0x56, 0x55,
			0x5c, 0x5f, 0x5a, 0x59, 0x48, 0x4b, 0x4e, 0x4d, 0x44, 0x47, 0x42,
			0x41, 0xc0, 0xc3, 0xc6, 0xc5, 0xcc, 0xcf, 0xca, 0xc9, 0xd8, 0xdb,
			0xde, 0xdd, 0xd4, 0xd7, 0xd2, 0xd1, 0xf0, 0xf3, 0xf6, 0xf5, 0xfc,
			0xff, 0xfa, 0xf9, 0xe8, 0xeb, 0xee, 0xed, 0xe4, 0xe7, 0xe2, 0xe1,
			0xa0, 0xa3, 0xa6, 0xa5, 0xac, 0xaf, 0xaa, 0xa9, 0xb8, 0xbb, 0xbe,
			0xbd, 0xb4, 0xb7, 0xb2, 0xb1, 0x90, 0x93, 0x96, 0x95, 0x9c, 0x9f,
			0x9a, 0x99, 0x88, 0x8b, 0x8e, 0x8d, 0x84, 0x87, 0x82, 0x81, 0x9b,
			0x98, 0x9d, 0x9e, 0x97, 0x94, 0x91, 0x92, 0x83, 0x80, 0x85, 0x86,
			0x8f, 0x8c, 0x89, 0x8a, 0xab, 0xa8, 0xad, 0xae, 0xa7, 0xa4, 0xa1,
			0xa2, 0xb3, 0xb0, 0xb5, 0xb6, 0xbf, 0xbc, 0xb9, 0xba, 0xfb, 0xf8,
			0xfd, 0xfe, 0xf7, 0xf4, 0xf1, 0xf2, 0xe3, 0xe0, 0xe5, 0xe6, 0xef,
			0xec, 0xe9, 0xea, 0xcb, 0xc8, 0xcd, 0xce, 0xc7, 0xc4, 0xc1, 0xc2,
			0xd3, 0xd0, 0xd5, 0xd6, 0xdf, 0xdc, 0xd9, 0xda, 0x5b, 0x58, 0x5d,
			0x5e, 0x57, 0x54, 0x51, 0x52, 0x43, 0x40, 0x45, 0x46, 0x4f, 0x4c,
			0x49, 0x4a, 0x6b, 0x68, 0x6d, 0x6e, 0x67, 0x64, 0x61, 0x62, 0x73,
			0x70, 0x75, 0x76, 0x7f, 0x7c, 0x79, 0x7a, 0x3b, 0x38, 0x3d, 0x3e,
			0x37, 0x34, 0x31, 0x32, 0x23, 0x20, 0x25, 0x26, 0x2f, 0x2c, 0x29,
			0x2a, 0x0b, 0x08, 0x0d, 0x0e, 0x07, 0x04, 0x01, 0x02, 0x13, 0x10,
			0x15, 0x16, 0x1f, 0x1c, 0x19, 0x1a };
	// It will create two-dimensional array of keyMatrix[4][4]
	public static String[][] keyMatrix;
	// It will create two-dimensional array of WMatrix[][]
	public static String[][] WMatrix;

	public static int Nc = 0;
	public static int wCols = 0;

	public static void getDetails(String KeyHex) {
		if (KeyHex.length() == 32) {
			Nc = 4;
			wCols = 44;
		}
		if (KeyHex.length() == 48) {
			Nc = 6;
			wCols = 52;
		}
		if (KeyHex.length() == 64) {
			Nc = 8;
			wCols = 60;
		}
		keyMatrix = new String[4][Nc];
		WMatrix = new String[4][wCols];
	}

	/**
	 * aesRoundKeys
	 * 
	 * This function takes the key value as 4*4 matrix and performs split
	 * operation on it.It will split the string[][] for every 2-bits and calls
	 * getWMatrix() and printKeys() on it.
	 * 
	 * @param KeyHex
	 *            is the encryption key
	 */
	public static void aesRoundKeys(String KeyHex) {
		int value = 0;
		// keyMatrix = new String[4][4];
		for (int j = 0; j < Nc; j++) {
			for (int i = 0; i < 4; i++) {
				// Splits the key for every 2 values using subString() method.
				keyMatrix[i][j] = KeyHex.substring(value, value + 2);
				value += 2;
			}
		}
		getWMatrix();
	}

	/**
	 * ComputeXOR
	 * 
	 * This function performs bitwise XOR of two matrices with 4 elements each.
	 * 
	 * @param hex1
	 *            is the first value
	 * @param hex2
	 *            is the second value
	 * @return hexResult is the XOR result
	 */
	private static String ComputeXOR(String hex1, String hex2) {
		int hexVal1 = Integer.parseInt(hex1, 16);
		int hexVal2 = Integer.parseInt(hex2, 16);
		int hexResult = hexVal1 ^ hexVal2;
		String hexXORResult = Integer.toHexString(hexResult);
		return hexXORResult.length() == 1 ? ("0" + hexXORResult) : hexXORResult;
	}

	/**
	 * aesSBox This function returns the corresponding hex integer by referring
	 * the look up table
	 * 
	 * @param inHex
	 *            input hexadecimal to produce integer value
	 * @return the transformed value from look up table
	 */
	private static String aesSBox(String inHex) {
		Integer firstInt = Integer.parseInt(inHex.split("")[0], 16);
		Integer secondInt = Integer.parseInt(inHex.split("")[1], 16);
		return S_Box[firstInt][secondInt];
	}

	/**
	 * aesRcon This function returns a round constant value
	 * 
	 * @param round
	 *            is the round number which we are going to use everytime
	 *            usually it ranges between 0 to 10
	 * @return the corresponding round value from lookup table
	 */
	private static String aesRcon(int round) {
		return Round_Keys[0][round / Nc];
	}

	/**
	 * getWMatrix This function generates 11 round keys using an encryption key.
	 * In this we are copying the 1st 4*4 matrix then performing the operations
	 * based on whether the value of j is multiple of 4 or not.
	 * 
	 */

	private static void getWMatrix() {
		// It will create the new matrix
		String W_New[][] = new String[1][4];
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < Nc; j++) {
				WMatrix[i][j] = keyMatrix[i][j];
			}
		}
		for (int j = Nc; j < wCols; j++) {
			// If j value is not multiple of 4 then
			if (j % Nc != 0) {
				if (Nc == 8 && j % 4 == 0) {
					W_New[0][0] = aesSBox(WMatrix[0][j - 1]);
					W_New[0][1] = aesSBox(WMatrix[1][j - 1]);
					W_New[0][2] = aesSBox(WMatrix[2][j - 1]);
					W_New[0][3] = aesSBox(WMatrix[3][j - 1]);
					for (int i = 0; i < 4; i++) {
						WMatrix[i][j] = ComputeXOR(WMatrix[i][j - 8],
								W_New[0][i]);
					}
				} else {
					for (int i = 0; i < 4; i++) {
						WMatrix[i][j] = ComputeXOR(WMatrix[i][j - Nc],
								WMatrix[i][j - 1]);
					}
				}
			} else {
				// Performing left shift operation and transpose of matrix
				W_New[0][0] = aesSBox(WMatrix[1][j - 1]);
				W_New[0][1] = aesSBox(WMatrix[2][j - 1]);
				W_New[0][2] = aesSBox(WMatrix[3][j - 1]);
				W_New[0][3] = aesSBox(WMatrix[0][j - 1]);
				// XOR the Rcon_value with the new matrix
				String Rcon_Val = aesRcon(j);
				W_New[0][0] = ComputeXOR(Rcon_Val, W_New[0][0]);
				for (int i = 0; i < 4; i++) {
					WMatrix[i][j] = ComputeXOR(WMatrix[i][j - Nc], W_New[0][i]);
				}
			}
		}
	}

	/**
	 * This function performs XOR operation on two 4*4 matrices and outputs the
	 * result
	 * 
	 * @param sHex
	 *            is the first input matrix
	 * @param keyHex
	 *            is the second input matrix
	 * @return outStateHex which have the XORed result
	 */
	protected static String[][] aesStateXOR(String[][] sHex, String[][] keyHex) {
		String[][] outStateHex;
		outStateHex = new String[4][4];
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				outStateHex[i][j] = ComputeXOR(sHex[i][j], keyHex[i][j]);
			}
		}
		return outStateHex;
	}

	/**
	 * This function substitutes its each element with its corresponding S-Box
	 * value
	 * 
	 * @param inStateHex
	 *            is the input matrix
	 * @return outStateHex is substituted matrix
	 */
	protected static String[][] aesNibbleSub(String[][] inStateHex) {
		String[][] outStateHex = new String[4][4];
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				outStateHex[i][j] = aesSBox(inStateHex[i][j]);
			}
		}
		return outStateHex;
	}

	/**
	 * This function performs left shift operation on each element
	 * 
	 * @param inStateHex
	 *            is the input matrix with size 4*4
	 * @return outStateHex is the shifted matrix with size 4*4
	 */
	protected static String[][] aesShiftRow(String[][] inStateHex) {
		int counter = 0;
		String[][] outStateHex = new String[4][4];
		String[] tempState = new String[4];
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				tempState[j] = inStateHex[i][j];
			}
			for (int k = 0; k < counter; k++) {
				String newValue = tempState[0];
				tempState[0] = tempState[1];
				tempState[1] = tempState[2];
				tempState[2] = tempState[3];
				tempState[3] = newValue;
			}
			for (int n = 0; n < 4; n++) {
				outStateHex[i][n] = tempState[n];
			}
			counter++;
		}
		insertMap();
		return outStateHex;
	}

	/**
	 * It will insert values into the hashmap i2Map and i3Map
	 */
	public static void insertMap() {
		for (int i2Map = 0; i2Map < 256; i2Map++) {
			mul2.put(i2Map, mc2[i2Map]);
		}
		for (int i3Map = 0; i3Map < 256; i3Map++) {
			mul3.put(i3Map, mc3[i3Map]);

		}
	}

	/**
	 * It makes use of Multiplication look up tables to multiply the columns of
	 * input matrix
	 * 
	 * @param inStateHex
	 *            the input matrix
	 * @return outStateMatrix the output matrix
	 */
	protected static String[][] aesMixColumn(String[][] inStateHex) {
		String[][] copyMatrix = new String[4][4];
		copyMatrix = inStateHex;
		String[][] outStateHex = new String[4][4];
		int inputText[] = new int[4];
		int mixOut[] = new int[4];
		for (int row = 0; row < 4; row++) {
			for (int col = 0; col < 4; col++) {
			}
		}
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				inputText[j] = Integer.parseInt(copyMatrix[j][i], 16);
			}
			mixOut[0] = mul2.get(inputText[0]) ^ mul3.get(inputText[1])
					^ inputText[2] ^ inputText[3];
			mixOut[1] = inputText[0] ^ mul2.get(inputText[1])
					^ mul3.get(inputText[2]) ^ inputText[3];
			mixOut[2] = inputText[0] ^ inputText[1] ^ mul2.get(inputText[2])
					^ mul3.get(inputText[3]);
			mixOut[3] = mul3.get(inputText[0]) ^ inputText[1] ^ inputText[2]
					^ mul2.get(inputText[3]);
			for (int k = 0; k < 4; k++) {
				outStateHex[k][i] = Integer.toHexString(mixOut[k]);
			}
		}
		return outStateHex;
	}

	static String[][] plainText1 = new String[4][4];

	/**
	 * This function takes plaintext String and converts it into matrix
	 * 
	 * @param text
	 *            is the input plaintext
	 */
	public static void plainMatrix(String plainText) {
		int value = 0;
		for (int j = 0; j < 4; j++) {
			for (int i = 0; i < 4; i++) {
				// Splits the key for every 2 values using subString() method.
				plainText1[i][j] = plainText.substring(value, value + 2);
				value += 2;
			}
		}
	}

	/**
	 * This method will perform encryption of plaintext using hexadecimal key
	 * input.
	 * 
	 * @param pTextHex
	 *            is the plaintext we want to encrypt
	 * @param keyHex
	 *            is the key value to be used
	 */
	static int rounds = 0;

	public static void aes(String pTextHex, String keyHex) {
		plainMatrix(pTextHex);
		getDetails(keyHex);
		int wcol = 0;
		int count = 0;
		int roundCount = 0;
		int wColVal = 0;
		if (keyHex.length() == 32) {
			roundCount = 10;
			wColVal = 44;
		}
		if (keyHex.length() == 48) {
			wColVal = 52;
			roundCount = 12;
		}
		if (keyHex.length() == 64) {
			wColVal = 60;
			roundCount = 14;
		}
		aesRoundKeys(keyHex);

		while (wcol < wColVal) {
			for (int col = 0; col < 4; col++, wcol++) {
				for (int row = 0; row < 4; row++) {
					keyMatrix[row][col] = WMatrix[row][wcol];
				}
			}
			if (count == roundCount) {
				plainText1 = aesStateXOR(plainText1, keyMatrix);
				System.out.print("Cipher text is:");
				for (int i = 0; i < 4; i++) {
					for (int j = 0; j < 4; j++) {
						System.out.print(plainText1[j][i].toUpperCase());
					}
				}
			} else {
				rounds = count++;
				plainText1 = aesStateXOR(plainText1, keyMatrix);
				plainText1 = aesNibbleSub(plainText1);
				plainText1 = aesShiftRow(plainText1);
				if (rounds != roundCount - 1) {
					plainText1 = aesMixColumn(plainText1);
				}
			}
		}
	}
}