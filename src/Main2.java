/*
Vivian Tran, Gil Rabara, Andrew Nguyen
TCSS 487 Cryptography Project (Part 1)
5/7/2023
 */

import java.awt.*;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Scanner;

public class Main2 {
    final static Scanner scnr = new Scanner(System.in);
    public static void main(String args[]) {
        System.out.print("Enter your desired function: \nH (hash) " +
                "\nM (MAC) \nE (Encrypt) \nD (Decrypt)\nQ (Quit) \n>> ");
        String function = scnr.nextLine();
        while(!function.equalsIgnoreCase("Q")) {
        System.out.print("Would you like to input a: \nF (file) \nT (text)\n>> ");
        String input = scnr.nextLine();
        System.out.print("Would you like to output a: \nF (file) \nT (text)\n>> ");
        String output = scnr.nextLine();

            switch (function) {
                case "H":
                case "h":
                    byte[] data = getData(input);
                    byte[] crypto = hash("".getBytes(), data);
                    if (output.equalsIgnoreCase("f")) {
                        System.out.println("Enter folder path:");
                        String folderPath = scnr.nextLine();
                        outputFile(folderPath + "\\Hash.txt", crypto);
                    } else {
                        System.out.println("The hash of your text is: " + convertBytesToHex(crypto) + "\n");
                        //printByteData(crypto);
                    }
                    break;
                case "M":
                case "m":
                    byte[] key = getKey(input);
                    byte[] data1 = getData(input);
                    byte[] crypto1 = hash(key, data1);
                    if (output.equalsIgnoreCase("f")) {
                        System.out.println("Enter folder path:");
                        String folderPath = scnr.nextLine();
                        outputFile(folderPath + "\\MAC.txt", crypto1);
                    } else {
                        System.out.println(convertBytesToHex(crypto1));
                        //printByteData(crypto);
                    }
                    break;
                case "E":
                case "e":
                    byte[] key1 = getKey(input);
                    byte[] data2 = getData(input);
                    encrypt(key1, data2, output);
                    break;
                case "D":
                case "d":
                    byte[] crypto2 = getData(input);
                    byte[] key2 = getKey(input);
                    byte[] z = new byte[64];
                    byte[] c = new byte[crypto2.length - 128];
                    byte[] t = new byte[64];
                    System.arraycopy(crypto2, 0, z, 0, 64);
                    System.arraycopy(crypto2, 64, c, 0, crypto2.length - 128);
                    System.arraycopy(crypto2, crypto2.length - 64, t, 0, 64);
                    byte[] message = decrypt(z, key2, c, t);
                    if (output.equalsIgnoreCase("f")) {
                        System.out.print("Enter folder path: \n>> ");
                        String folderPath = scnr.nextLine();
                        outputFile(folderPath + "\\Crypto.txt", crypto2);
                    } else {
                        // System.out.println(byteToString(crypto2));

                        //printByteData(message);
                        //System.out.println(hexToString(crypto2.toString()));
                        System.out.println(convertBytesToHex(crypto2));
                        System.out.println(convertBytesToHex(message));
                    }
                    break;

                default:
                    System.out.println("Invalid mode selected.\n>>>>>>>>>> EXITING PROGRAM <<<<<<<<<<<");
                    break;
            }
            System.out.print("Enter your desired function: \nH (hash) " +
                    "\nM (MAC) \nE (Encrypt) \nD (Decrypt)\nQ (Quit) \n>> ");
             function = scnr.nextLine();

        }
        if(function.equalsIgnoreCase("Q")){
                System.out.println(">>>>>>>>>> EXITING PROGRAM <<<<<<<<<<<");
        }
    }

    /**
     * Get input data from user
     * @param input either input File or Text
     * @return read the file, or return the bytes of the text
     */
    private static byte[] getData(String input) {
        String out = "";
        if (input.equalsIgnoreCase("F")) {
            return readFile();
        } else if(input.equalsIgnoreCase("T")){
            System.out.print("Enter text: \n>> ");
            out =  scnr.nextLine();
            return out.getBytes();
        }
        return null;
    }

    /**
     * if user chose to input a file, read the text from file
     * @return text within the file in bytes
     */
    private static byte[] readFile() {
        System.out.print("Enter file path: \n>> ");
        String filePath = scnr.nextLine();
        try (FileInputStream fileInput = new FileInputStream(filePath)) {
            byte[] fileData = fileInput.readAllBytes();
            return fileData;
        } catch (IOException e) {
            System.out.println("Error: file input is not valid!");
            System.exit(0);
            return null;
        }
    }

    /**
     * if user has chosen to get the output in a file form, then write to created file from path given
     * @param filePath filepath given from user
     * @param data data from the function chosen in order to write to file
     */
    private static void outputFile(String filePath, byte[] data) {
        try (FileOutputStream outputStream = new FileOutputStream(filePath)) {
            outputStream.write(data);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * prints the function results into byte form (1's and 0's)
     * @param data user input data
     */
    private static void printByteData(byte[] data) {
       // System.out.println(convertBytesToHex(data)); //test
        StringBuilder sb = new StringBuilder();
        for (int index = 0; index < data.length; index++) {
            sb.append(" ").append(byteToString(data[index]));
        }
        System.out.println("Result: " +  sb.toString());
    }


    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    /**
     * converts bytes in to hexadecimal form
     * @param bytes bytes given in order to convert to hex
     * @return hex conversion of given byte array
     */
    private static String convertBytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            hexChars[i * 2] = HEX_ARRAY[v >>> 4];
            hexChars[i * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * converts byte to string
     * @param toConvert
     * @return
     */
    private static String byteToString(byte toConvert) {
        StringBuilder toReturn = new StringBuilder(8);

        for (int bitIndex = 7; bitIndex >= 0; bitIndex--) {
            int bit = (toConvert >> bitIndex) & 0x01;
            toReturn.append(bit);
        }

        return toReturn.toString();
    }
    private static String hexToString(String hexString){
        StringBuilder output = new StringBuilder();
        for (int i = 0; i < hexString.length(); i += 2) {
            String str = hexString.substring(i, i + 2);
            output.append((char) Integer.parseInt(str, 16));
        }
        return output.toString();
    }

    private static byte[] hash(byte[] key, byte[] data) {
        KMACXOF256 sponge = new KMACXOF256(key, data, 512, "T");
        return sponge.retrieveData();
    }

    private static byte[] getKey(String inputChoice) {
        System.out.println();
        if (inputChoice.equals("1")) {
            System.out.print("Enter key filename: \n>> ");
            return readFile();
        } else {
            System.out.print("Enter key: \n>> ");
            String key = scnr.nextLine();
            return key.getBytes();
        }
    }
    private static void encrypt(byte[] key, byte[] data, String output) {
        // getting a random 512 bit value
        SecureRandom secureRandom = new SecureRandom();
        byte[] initVal = new byte[64];
        secureRandom.nextBytes(initVal);

        // calculate ke and ka
        byte[] keccak = (new KMACXOF256(addBytes(initVal, key), new byte[0], 1024, "S")).retrieveData();
        byte[] ke = Arrays.copyOfRange(keccak, 0, keccak.length / 2);
        byte[] ka = Arrays.copyOfRange(keccak, keccak.length / 2, keccak.length);

        // encrypted message
        byte[] c = xorBytes((new KMACXOF256(ke, new byte[0], data.length * 8, "SKE")).retrieveData(), data);
        // MAC
        byte[] t = (new KMACXOF256(ka, data, 512, "SKA")).retrieveData();

        // Populate the cryptogram: cryptogram = (z | c | t)
        ByteBuffer bb = ByteBuffer.allocate(initVal.length + c.length + t.length)
                .put(initVal).put(c).put(t);
        byte[] cryptogram = bb.array();

        if (output.equalsIgnoreCase("F")) {
            System.out.println("Enter folder path:");
            String folderPath = scnr.nextLine();
            outputFile(folderPath + "\\cryptogram.txt", cryptogram);
        } else {
            System.out.println(convertBytesToHex(cryptogram));
            //printByteData(cryptogram);
        }
    }
    private static byte[] decrypt(byte[] iv, byte[] key, byte[] c, byte[] t) {
        byte[] keka = (new KMACXOF256(addBytes(iv, key), "".getBytes(), 1024, "S")).retrieveData();
        byte[] ke = Arrays.copyOfRange(keka, 0, keka.length / 2);
        byte[] ka = Arrays.copyOfRange(keka, keka.length / 2, keka.length);

        byte[] m = xorBytes((new KMACXOF256(ke, "".getBytes(), c.length * 8, "SKE")).retrieveData(), c);
        byte[] tPrime = (new KMACXOF256(ka, m, 512, "SKA")).retrieveData();

        if (Arrays.equals(tPrime, t)) {
            return m;
        } else {
            return null;
        }
    }

    private static byte[] addBytes(byte[] b1, byte[] b2) {
        byte[] out = new byte[b1.length + b2.length];
        System.arraycopy(b1, 0, out, 0, b1.length);
        System.arraycopy(b2, 0, out, b1.length, b2.length);
        return out;
    }
    private static byte[] xorBytes(byte[] b1, byte[] b2) {
        int totalLen = Math.min(b1.length, b2.length);
        byte[] result = new byte[totalLen];
        for (int i = 0; i < totalLen; i++) {
            result[i] = (byte) (b1[i] ^ b2[i]);
        }
        return result;
    }
}


