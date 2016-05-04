import java.util.HashMap;

/**
 * file: AESDecrypt.java 
 * author: Himaja Kethiri, Sandeep Reddy Salla 
 * course: Security Algorithms and Protocols 
 * Project: AES Encryption and Decryption for 128, 192 and 256 bits  
 * Due date: May 2, 2016 
 * version: 1.0
 * 
 * This file contains the methods to Decrypts the cipher text using the key
 * of 128, 192 and 256 bits.
 * 
 */

public class AESDecrypt {
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
    // INV_S_Box is a inverse substitute box which is an array
    private static final String[][] INV_S_BOX = {
            { "52", "09", "6A", "D5", "30", "36", "A5", "38", "BF", "40", "A3",
                    "9E", "81", "F3", "D7", "FB" },
            { "7C", "E3", "39", "82", "9B", "2F", "FF", "87", "34", "8E", "43",
                    "44", "C4", "DE", "E9", "CB" },
            { "54", "7B", "94", "32", "A6", "C2", "23", "3D", "EE", "4C", "95",
                    "0B", "42", "FA", "C3", "4E" },
            { "08", "2E", "A1", "66", "28", "D9", "24", "B2", "76", "5B", "A2",
                    "49", "6D", "8B", "D1", "25" },
            { "72", "F8", "F6", "64", "86", "68", "98", "16", "D4", "A4", "5C",
                    "CC", "5D", "65", "B6", "92" },
            { "6C", "70", "48", "50", "FD", "ED", "B9", "DA", "5E", "15", "46",
                    "57", "A7", "8D", "9D", "84" },
            { "90", "D8", "AB", "00", "8C", "BC", "D3", "0A", "F7", "E4", "58",
                    "05", "B8", "B3", "45", "06" },
            { "D0", "2C", "1E", "8F", "CA", "3F", "0F", "02", "C1", "AF", "BD",
                    "03", "01", "13", "8A", "6B" },
            { "3A", "91", "11", "41", "4F", "67", "DC", "EA", "97", "F2", "CF",
                    "CE", "F0", "B4", "E6", "73" },
            { "96", "AC", "74", "22", "E7", "AD", "35", "85", "E2", "F9", "37",
                    "E8", "1C", "75", "DF", "6E" },
            { "47", "F1", "1A", "71", "1D", "29", "C5", "89", "6F", "B7", "62",
                    "0E", "AA", "18", "BE", "1B" },
            { "FC", "56", "3E", "4B", "C6", "D2", "79", "20", "9A", "DB", "C0",
                    "FE", "78", "CD", "5A", "F4" },
            { "1F", "DD", "A8", "33", "88", "07", "C7", "31", "B1", "12", "10",
                    "59", "27", "80", "EC", "5F" },
            { "60", "51", "7F", "A9", "19", "B5", "4A", "0D", "2D", "E5", "7A",
                    "9F", "93", "C9", "9C", "EF" },
            { "A0", "E0", "3B", "4D", "AE", "2A", "F5", "B0", "C8", "EB", "BB",
                    "3C", "83", "53", "99", "61" },
            { "17", "2B", "04", "7E", "BA", "77", "D6", "26", "E1", "69", "14",
                    "63", "55", "21", "0C", "7D" } };
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
    // Creating mul9 hashmap with integer values
    public static HashMap<Integer, Integer> mul9 = new HashMap<Integer, Integer>();
    // Creating mul11 hashmap with integer values
    public static HashMap<Integer, Integer> mul11 = new HashMap<Integer, Integer>();
    // Creating mul13 hashmap with integer values
    public static HashMap<Integer, Integer> mul13 = new HashMap<Integer, Integer>();
    // Creating mul14 hashmap with integer values
    public static HashMap<Integer, Integer> mul14 = new HashMap<Integer, Integer>();
    // Multiplication with 9 look-up table
    public static int[] mc9 = { 0x00, 0x09, 0x12, 0x1b, 0x24, 0x2d, 0x36, 0x3f,
            0x48, 0x41, 0x5a, 0x53, 0x6c, 0x65, 0x7e, 0x77, 0x90, 0x99, 0x82,
            0x8b, 0xb4, 0xbd, 0xa6, 0xaf, 0xd8, 0xd1, 0xca, 0xc3, 0xfc, 0xf5,
            0xee, 0xe7, 0x3b, 0x32, 0x29, 0x20, 0x1f, 0x16, 0x0d, 0x04, 0x73,
            0x7a, 0x61, 0x68, 0x57, 0x5e, 0x45, 0x4c, 0xab, 0xa2, 0xb9, 0xb0,
            0x8f, 0x86, 0x9d, 0x94, 0xe3, 0xea, 0xf1, 0xf8, 0xc7, 0xce, 0xd5,
            0xdc, 0x76, 0x7f, 0x64, 0x6d, 0x52, 0x5b, 0x40, 0x49, 0x3e, 0x37,
            0x2c, 0x25, 0x1a, 0x13, 0x08, 0x01, 0xe6, 0xef, 0xf4, 0xfd, 0xc2,
            0xcb, 0xd0, 0xd9, 0xae, 0xa7, 0xbc, 0xb5, 0x8a, 0x83, 0x98, 0x91,
            0x4d, 0x44, 0x5f, 0x56, 0x69, 0x60, 0x7b, 0x72, 0x05, 0x0c, 0x17,
            0x1e, 0x21, 0x28, 0x33, 0x3a, 0xdd, 0xd4, 0xcf, 0xc6, 0xf9, 0xf0,
            0xeb, 0xe2, 0x95, 0x9c, 0x87, 0x8e, 0xb1, 0xb8, 0xa3, 0xaa, 0xec,
            0xe5, 0xfe, 0xf7, 0xc8, 0xc1, 0xda, 0xd3, 0xa4, 0xad, 0xb6, 0xbf,
            0x80, 0x89, 0x92, 0x9b, 0x7c, 0x75, 0x6e, 0x67, 0x58, 0x51, 0x4a,
            0x43, 0x34, 0x3d, 0x26, 0x2f, 0x10, 0x19, 0x02, 0x0b, 0xd7, 0xde,
            0xc5, 0xcc, 0xf3, 0xfa, 0xe1, 0xe8, 0x9f, 0x96, 0x8d, 0x84, 0xbb,
            0xb2, 0xa9, 0xa0, 0x47, 0x4e, 0x55, 0x5c, 0x63, 0x6a, 0x71, 0x78,
            0x0f, 0x06, 0x1d, 0x14, 0x2b, 0x22, 0x39, 0x30, 0x9a, 0x93, 0x88,
            0x81, 0xbe, 0xb7, 0xac, 0xa5, 0xd2, 0xdb, 0xc0, 0xc9, 0xf6, 0xff,
            0xe4, 0xed, 0x0a, 0x03, 0x18, 0x11, 0x2e, 0x27, 0x3c, 0x35, 0x42,
            0x4b, 0x50, 0x59, 0x66, 0x6f, 0x74, 0x7d, 0xa1, 0xa8, 0xb3, 0xba,
            0x85, 0x8c, 0x97, 0x9e, 0xe9, 0xe0, 0xfb, 0xf2, 0xcd, 0xc4, 0xdf,
            0xd6, 0x31, 0x38, 0x23, 0x2a, 0x15, 0x1c, 0x07, 0x0e, 0x79, 0x70,
            0x6b, 0x62, 0x5d, 0x54, 0x4f, 0x46 };
    // Multiplication with 11 look-up table
    public static int[] mc11 = { 0x00, 0x0b, 0x16, 0x1d, 0x2c, 0x27, 0x3a,
            0x31, 0x58, 0x53, 0x4e, 0x45, 0x74, 0x7f, 0x62, 0x69, 0xb0, 0xbb,
            0xa6, 0xad, 0x9c, 0x97, 0x8a, 0x81, 0xe8, 0xe3, 0xfe, 0xf5, 0xc4,
            0xcf, 0xd2, 0xd9, 0x7b, 0x70, 0x6d, 0x66, 0x57, 0x5c, 0x41, 0x4a,
            0x23, 0x28, 0x35, 0x3e, 0x0f, 0x04, 0x19, 0x12, 0xcb, 0xc0, 0xdd,
            0xd6, 0xe7, 0xec, 0xf1, 0xfa, 0x93, 0x98, 0x85, 0x8e, 0xbf, 0xb4,
            0xa9, 0xa2, 0xf6, 0xfd, 0xe0, 0xeb, 0xda, 0xd1, 0xcc, 0xc7, 0xae,
            0xa5, 0xb8, 0xb3, 0x82, 0x89, 0x94, 0x9f, 0x46, 0x4d, 0x50, 0x5b,
            0x6a, 0x61, 0x7c, 0x77, 0x1e, 0x15, 0x08, 0x03, 0x32, 0x39, 0x24,
            0x2f, 0x8d, 0x86, 0x9b, 0x90, 0xa1, 0xaa, 0xb7, 0xbc, 0xd5, 0xde,
            0xc3, 0xc8, 0xf9, 0xf2, 0xef, 0xe4, 0x3d, 0x36, 0x2b, 0x20, 0x11,
            0x1a, 0x07, 0x0c, 0x65, 0x6e, 0x73, 0x78, 0x49, 0x42, 0x5f, 0x54,
            0xf7, 0xfc, 0xe1, 0xea, 0xdb, 0xd0, 0xcd, 0xc6, 0xaf, 0xa4, 0xb9,
            0xb2, 0x83, 0x88, 0x95, 0x9e, 0x47, 0x4c, 0x51, 0x5a, 0x6b, 0x60,
            0x7d, 0x76, 0x1f, 0x14, 0x09, 0x02, 0x33, 0x38, 0x25, 0x2e, 0x8c,
            0x87, 0x9a, 0x91, 0xa0, 0xab, 0xb6, 0xbd, 0xd4, 0xdf, 0xc2, 0xc9,
            0xf8, 0xf3, 0xee, 0xe5, 0x3c, 0x37, 0x2a, 0x21, 0x10, 0x1b, 0x06,
            0x0d, 0x64, 0x6f, 0x72, 0x79, 0x48, 0x43, 0x5e, 0x55, 0x01, 0x0a,
            0x17, 0x1c, 0x2d, 0x26, 0x3b, 0x30, 0x59, 0x52, 0x4f, 0x44, 0x75,
            0x7e, 0x63, 0x68, 0xb1, 0xba, 0xa7, 0xac, 0x9d, 0x96, 0x8b, 0x80,
            0xe9, 0xe2, 0xff, 0xf4, 0xc5, 0xce, 0xd3, 0xd8, 0x7a, 0x71, 0x6c,
            0x67, 0x56, 0x5d, 0x40, 0x4b, 0x22, 0x29, 0x34, 0x3f, 0x0e, 0x05,
            0x18, 0x13, 0xca, 0xc1, 0xdc, 0xd7, 0xe6, 0xed, 0xf0, 0xfb, 0x92,
            0x99, 0x84, 0x8f, 0xbe, 0xb5, 0xa8, 0xa3 };
    // Multiplication with 13 look-up table
    public static int[] mc13 = { 0x00, 0x0d, 0x1a, 0x17, 0x34, 0x39, 0x2e,
            0x23, 0x68, 0x65, 0x72, 0x7f, 0x5c, 0x51, 0x46, 0x4b, 0xd0, 0xdd,
            0xca, 0xc7, 0xe4, 0xe9, 0xfe, 0xf3, 0xb8, 0xb5, 0xa2, 0xaf, 0x8c,
            0x81, 0x96, 0x9b, 0xbb, 0xb6, 0xa1, 0xac, 0x8f, 0x82, 0x95, 0x98,
            0xd3, 0xde, 0xc9, 0xc4, 0xe7, 0xea, 0xfd, 0xf0, 0x6b, 0x66, 0x71,
            0x7c, 0x5f, 0x52, 0x45, 0x48, 0x03, 0x0e, 0x19, 0x14, 0x37, 0x3a,
            0x2d, 0x20, 0x6d, 0x60, 0x77, 0x7a, 0x59, 0x54, 0x43, 0x4e, 0x05,
            0x08, 0x1f, 0x12, 0x31, 0x3c, 0x2b, 0x26, 0xbd, 0xb0, 0xa7, 0xaa,
            0x89, 0x84, 0x93, 0x9e, 0xd5, 0xd8, 0xcf, 0xc2, 0xe1, 0xec, 0xfb,
            0xf6, 0xd6, 0xdb, 0xcc, 0xc1, 0xe2, 0xef, 0xf8, 0xf5, 0xbe, 0xb3,
            0xa4, 0xa9, 0x8a, 0x87, 0x90, 0x9d, 0x06, 0x0b, 0x1c, 0x11, 0x32,
            0x3f, 0x28, 0x25, 0x6e, 0x63, 0x74, 0x79, 0x5a, 0x57, 0x40, 0x4d,
            0xda, 0xd7, 0xc0, 0xcd, 0xee, 0xe3, 0xf4, 0xf9, 0xb2, 0xbf, 0xa8,
            0xa5, 0x86, 0x8b, 0x9c, 0x91, 0x0a, 0x07, 0x10, 0x1d, 0x3e, 0x33,
            0x24, 0x29, 0x62, 0x6f, 0x78, 0x75, 0x56, 0x5b, 0x4c, 0x41, 0x61,
            0x6c, 0x7b, 0x76, 0x55, 0x58, 0x4f, 0x42, 0x09, 0x04, 0x13, 0x1e,
            0x3d, 0x30, 0x27, 0x2a, 0xb1, 0xbc, 0xab, 0xa6, 0x85, 0x88, 0x9f,
            0x92, 0xd9, 0xd4, 0xc3, 0xce, 0xed, 0xe0, 0xf7, 0xfa, 0xb7, 0xba,
            0xad, 0xa0, 0x83, 0x8e, 0x99, 0x94, 0xdf, 0xd2, 0xc5, 0xc8, 0xeb,
            0xe6, 0xf1, 0xfc, 0x67, 0x6a, 0x7d, 0x70, 0x53, 0x5e, 0x49, 0x44,
            0x0f, 0x02, 0x15, 0x18, 0x3b, 0x36, 0x21, 0x2c, 0x0c, 0x01, 0x16,
            0x1b, 0x38, 0x35, 0x22, 0x2f, 0x64, 0x69, 0x7e, 0x73, 0x50, 0x5d,
            0x4a, 0x47, 0xdc, 0xd1, 0xc6, 0xcb, 0xe8, 0xe5, 0xf2, 0xff, 0xb4,
            0xb9, 0xae, 0xa3, 0x80, 0x8d, 0x9a, 0x97 };
    // Multiplication with 14 look-up table
    public static int[] mc14 = { 0x00, 0x0e, 0x1c, 0x12, 0x38, 0x36, 0x24,
            0x2a, 0x70, 0x7e, 0x6c, 0x62, 0x48, 0x46, 0x54, 0x5a, 0xe0, 0xee,
            0xfc, 0xf2, 0xd8, 0xd6, 0xc4, 0xca, 0x90, 0x9e, 0x8c, 0x82, 0xa8,
            0xa6, 0xb4, 0xba, 0xdb, 0xd5, 0xc7, 0xc9, 0xe3, 0xed, 0xff, 0xf1,
            0xab, 0xa5, 0xb7, 0xb9, 0x93, 0x9d, 0x8f, 0x81, 0x3b, 0x35, 0x27,
            0x29, 0x03, 0x0d, 0x1f, 0x11, 0x4b, 0x45, 0x57, 0x59, 0x73, 0x7d,
            0x6f, 0x61, 0xad, 0xa3, 0xb1, 0xbf, 0x95, 0x9b, 0x89, 0x87, 0xdd,
            0xd3, 0xc1, 0xcf, 0xe5, 0xeb, 0xf9, 0xf7, 0x4d, 0x43, 0x51, 0x5f,
            0x75, 0x7b, 0x69, 0x67, 0x3d, 0x33, 0x21, 0x2f, 0x05, 0x0b, 0x19,
            0x17, 0x76, 0x78, 0x6a, 0x64, 0x4e, 0x40, 0x52, 0x5c, 0x06, 0x08,
            0x1a, 0x14, 0x3e, 0x30, 0x22, 0x2c, 0x96, 0x98, 0x8a, 0x84, 0xae,
            0xa0, 0xb2, 0xbc, 0xe6, 0xe8, 0xfa, 0xf4, 0xde, 0xd0, 0xc2, 0xcc,
            0x41, 0x4f, 0x5d, 0x53, 0x79, 0x77, 0x65, 0x6b, 0x31, 0x3f, 0x2d,
            0x23, 0x09, 0x07, 0x15, 0x1b, 0xa1, 0xaf, 0xbd, 0xb3, 0x99, 0x97,
            0x85, 0x8b, 0xd1, 0xdf, 0xcd, 0xc3, 0xe9, 0xe7, 0xf5, 0xfb, 0x9a,
            0x94, 0x86, 0x88, 0xa2, 0xac, 0xbe, 0xb0, 0xea, 0xe4, 0xf6, 0xf8,
            0xd2, 0xdc, 0xce, 0xc0, 0x7a, 0x74, 0x66, 0x68, 0x42, 0x4c, 0x5e,
            0x50, 0x0a, 0x04, 0x16, 0x18, 0x32, 0x3c, 0x2e, 0x20, 0xec, 0xe2,
            0xf0, 0xfe, 0xd4, 0xda, 0xc8, 0xc6, 0x9c, 0x92, 0x80, 0x8e, 0xa4,
            0xaa, 0xb8, 0xb6, 0x0c, 0x02, 0x10, 0x1e, 0x34, 0x3a, 0x28, 0x26,
            0x7c, 0x72, 0x60, 0x6e, 0x44, 0x4a, 0x58, 0x56, 0x37, 0x39, 0x2b,
            0x25, 0x0f, 0x01, 0x13, 0x1d, 0x47, 0x49, 0x5b, 0x55, 0x7f, 0x71,
            0x63, 0x6d, 0xd7, 0xd9, 0xcb, 0xc5, 0xef, 0xe1, 0xf3, 0xfd, 0xa7,
            0xa9, 0xbb, 0xb5, 0x9f, 0x91, 0x83, 0x8d };
    // It will create two-dimensional array of keyMatrix[][]
    public static String[][] keyMatrix;
    // It will create two-dimensional array of WMatrix[][]
    public static String[][] WMatrix;
    public static int Nc = 0;
    public static int wCols = 0;

    /**
     * This method takes key as input and checks the length of the key. Based on
     * key length the wmatrix column value and round value wiil be selected.
     * 
     * @param KeyHex
     */
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
     * This method returns the corresponding hex integer by referring the look
     * up table
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
     * 
     * This method returns the corresponding hex integer by referring the look
     * up table which is INV_S_BOX
     * 
     * @param inHex
     *            input hexadecimal to produce integer value
     * @return the transformed value from look up table
     */
    private static String invAesSBox(String inHex) {
        Integer firstInt = Integer.parseInt(inHex.split("")[0], 16);
        Integer secondInt = Integer.parseInt(inHex.split("")[1], 16);
        return INV_S_BOX[firstInt][secondInt];
    }

    /**
     *
     * This method returns a round constant value
     * 
     * @param round
     *            is the round number which we are going to use everytime
     *            usually based on the key length 128,192,and 256
     * @return the corresponding round value from lookup table
     */
    private static String aesRcon(int round) {
        return Round_Keys[0][round / Nc];
    }

    /**
     * 
     * This function generates the round keys using an encryption key. In this
     * we are copying the 1st 4*4 matrix then performing the operations based on
     * whether the value of j is multiple of Nc or not.
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
            // Conditions to generate Wmatrix based on key length
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
     * This function substitutes its each element with its corresponding
     * INV-S-BOX value
     * 
     * @param inStateHex
     *            is the input matrix
     * @return outStateHex is substituted matrix
     */
    protected static String[][] aesNibbleSub(String[][] inStateHex) {
        String[][] outStateHex = new String[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                outStateHex[i][j] = invAesSBox(inStateHex[i][j]);
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
        int count = 4;
        String[][] outStateHex = new String[4][4];
        for (int row = 0; row < 4; row++) {
            for (int column = 0; column < 4; column++) {
                outStateHex[row][column] = inStateHex[row][(column + count) % 4];

            }
            count--;
        }
        insertMap();
        return outStateHex;
    }

    /**
     * 
     * This method will insert values into the hashmaps i9Map, i11Map, i13Map,
     * and i14Maps.
     */
    public static void insertMap() {

        for (int i9Map = 0; i9Map < 256; i9Map++) {
            mul9.put(i9Map, mc9[i9Map]);
        }
        for (int i11Map = 0; i11Map < 256; i11Map++) {
            mul11.put(i11Map, mc11[i11Map]);
        }

        for (int i13Map = 0; i13Map < 256; i13Map++) {
            mul13.put(i13Map, mc13[i13Map]);

        }
        for (int i14Map = 0; i14Map < 256; i14Map++) {
            mul14.put(i14Map, mc14[i14Map]);

        }
    }

    /**
     * This method makes use of Multiplication look up tables to multiply the
     * columns of input matrix
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
            mixOut[0] = mul14.get(inputText[0]) ^ mul11.get(inputText[1])
                    ^ mul13.get(inputText[2]) ^ mul9.get(inputText[3]);

            mixOut[1] = mul9.get(inputText[0]) ^ mul14.get(inputText[1])
                    ^ mul11.get(inputText[2]) ^ mul13.get(inputText[3]);

            mixOut[2] = mul13.get(inputText[0]) ^ mul9.get(inputText[1])
                    ^ mul14.get(inputText[2]) ^ mul11.get(inputText[3]);

            mixOut[3] = mul11.get(inputText[0]) ^ mul13.get(inputText[1])
                    ^ mul9.get(inputText[2]) ^ mul14.get(inputText[3]);
            for (int k = 0; k < 4; k++) {

                if (Integer.toHexString(mixOut[k]).length() == 1) {
                    outStateHex[k][i] = "0" + Integer.toHexString(mixOut[k]);
                } else {
                    outStateHex[k][i] = Integer.toHexString(mixOut[k]);
                }
            }
        }
        return outStateHex;
    }

    static String[][] cipherText = new String[4][4];

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
                cipherText[i][j] = plainText.substring(value, value + 2);
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

    public static void aes(String cTextHex, String keyHex) {
        plainMatrix(cTextHex);
        getDetails(keyHex);
        int wcol = 0;
        int count = 0;
        int roundCount = 0;
        // int wCol = 0;
        if (keyHex.length() == 32) {
            roundCount = 10;
            wcol = 44;
        }
        if (keyHex.length() == 48) {
            wcol = 52;
            roundCount = 12;
        }
        if (keyHex.length() == 64) {
            wcol = 60;
            roundCount = 14;
        }
        aesRoundKeys(keyHex);
        while (wcol > 0) {
            wcol -= 4;
            for (int col = 0; col < 4; col++, wcol++) {
                for (int row = 0; row < 4; row++) {
                    keyMatrix[row][col] = WMatrix[row][wcol];
                }
            }
            wcol -= 4;
            if (count == roundCount) {
                cipherText = aesStateXOR(cipherText, keyMatrix);
                System.out.print("Plain text is:");
                for (int i = 0; i < 4; i++) {
                    for (int j = 0; j < 4; j++) {
                        System.out.print(cipherText[j][i].toUpperCase());
                    }
                }
            }
            if (count >= 1 && count <= roundCount - 1) {
                rounds = count++;
                cipherText = aesStateXOR(cipherText, keyMatrix);
                if (rounds != roundCount) {
                    cipherText = aesMixColumn(cipherText);
                }
                cipherText = aesShiftRow(cipherText);
                cipherText = aesNibbleSub(cipherText);
            }
            if (count == 0) {
                cipherText = aesStateXOR(cipherText, keyMatrix);
                cipherText = aesNibbleSub(cipherText);
                cipherText = aesShiftRow(cipherText);
                rounds = count++;
            }
        }
    }
}