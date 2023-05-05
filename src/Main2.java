/*
Vivian Tran, Gil Rabara, Andrew Nguyen
TCSS 487 Cryptography Project (Part 1)
5/7/2023
 */

import java.awt.*;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
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
                        System.out.println("Enter output folder path:");
                        String folderPath = scnr.nextLine();
                        outputFile(folderPath + "\\Hash.txt", convertBytesToHex(crypto));
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
                        System.out.println("Enter output folder path:");
                        String folderPath = scnr.nextLine();
                        outputFile(folderPath + "\\MAC.txt", convertBytesToHex(crypto1));
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
                    decrypt(key2, hexStringToByteArray(new String(crypto2, StandardCharsets.UTF_8)), output);
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

        System.out.print("Enter input file path: \n>> ");
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
    private static void outputFile(String filePath, String data) {
        try (FileOutputStream outputStream = new FileOutputStream(filePath)) {
            outputStream.write(data.getBytes());
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
     * @param toConvert byte input given
     * @return string conversion of given byte
     */
    private static String byteToString(byte toConvert) {
        StringBuilder toReturn = new StringBuilder(8);

        for (int bitIndex = 7; bitIndex >= 0; bitIndex--) {
            int bit = (toConvert >> bitIndex) & 0x01;
            toReturn.append(bit);
        }

        return toReturn.toString();
    }

    /**
     * convert hexadecimal to string
     * @param hexString the hexadecimal string that is given
     * @return string conversion of given hexadecimal
     */
    private static String hexToString(String hexString){
        StringBuilder output = new StringBuilder();
        for (int i = 0; i < hexString.length(); i += 2) {
            String str = hexString.substring(i, i + 2);
            output.append((char) Integer.parseInt(str, 16));
        }
        return output.toString();
    }

    /**
     * hashes given data based on key
     * @param key passphrase or password given from user
     * @param data the text or text from file given from user
     * @return hashed value of data
     */
    private static byte[] hash(byte[] key, byte[] data) {
        KMACXOF256 sponge = new KMACXOF256(key, data, 512, "T");
        return sponge.retrieveData();
    }

    /**
     * get the passphrase/password/key from user
     * @param inputChoice user input choice of either File or Text
     * @return key given from user
     */
    private static byte[] getKey(String inputChoice) {
        System.out.println();
        if (inputChoice.equalsIgnoreCase("F")) {
            System.out.print("Enter key filename: \n>> ");
            String key = scnr.nextLine();
            try (FileInputStream fileInput = new FileInputStream(key)) {
                byte[] fileData = fileInput.readAllBytes();
                return fileData;
            } catch (IOException e) {
                System.out.println("Error: file input is not valid!");
                System.exit(0);
                return null;
            }
        } else {
            System.out.print("Enter key: \n>> ");
            String key = scnr.nextLine();
            return key.getBytes();
        }
    }

    /**
     * encrypt data that is given by user (if user chose "E" or "e")
     * @param key the password/passphrase/key given by user
     * @param data the text from input or file given by user
     * @param output the output type of either text or file
     */
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
            outputFile(folderPath + "\\cryptogram.txt", convertBytesToHex(cryptogram));
        } else {
            System.out.println(convertBytesToHex(cryptogram));
        }
    }

    /**
     * decrypt data that is given by user (if user chose "D" or "d")
     * @param key the password/passphrase/key given by user
     * @param cryptogram the encrypted data from input or file given by user
     * @param output the output type of either text or file
     */
    private static void decrypt(byte[] key, byte[] cryptogram, String output) {
        // parse the cryptogram into its components
        byte[] initVal = Arrays.copyOfRange(cryptogram, 0, 64);
        byte[] c = Arrays.copyOfRange(cryptogram, 64, cryptogram.length - 512 / 8);
        byte[] t = Arrays.copyOfRange(cryptogram, cryptogram.length - 512 / 8, cryptogram.length);

        // calculate ke and ka
        byte[] keccak = (new KMACXOF256(addBytes(initVal, key), new byte[0], 1024, "S")).retrieveData();
        byte[] ke = Arrays.copyOfRange(keccak, 0, keccak.length / 2);
        byte[] ka = Arrays.copyOfRange(keccak, keccak.length / 2, keccak.length);

        // verify the MAC
        byte[] t_prime = (new KMACXOF256(ka, c, 512, "SKA")).retrieveData();
        /* check this ?
        if (!Arrays.equals(t, t_prime)) {
            System.out.println("MAC verification failed. The message may have been tampered with.");
            return;
        }
         */
        // decrypt the message
        byte[] m = xorBytes((new KMACXOF256(ke, new byte[0], c.length * 8, "SKE")).retrieveData(), c);

        if (output.equalsIgnoreCase("F")) {
            System.out.println("Enter folder path:");
            String folderPath = scnr.nextLine();
            outputFile(folderPath + "\\message.txt", new String(m, StandardCharsets.UTF_8));
        } else {
            System.out.println(new String(m, StandardCharsets.UTF_8));
        }
    }

    public static String convertBytesToString(byte[] data) {
        String str = "";
        try {
            str = new String(data, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return str;
    }

    public static byte[] hexStringToByteArray(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }

    /**
     * add two given byte arrays together
     * @param b1 byte array 1
     * @param b2 byte array 2
     * @return one byte array with 2 of the given byte arrays
     */
    private static byte[] addBytes(byte[] b1, byte[] b2) {
        byte[] out = new byte[b1.length + b2.length];
        System.arraycopy(b1, 0, out, 0, b1.length);
        System.arraycopy(b2, 0, out, b1.length, b2.length);
        return out;
    }

    /**
     * takes two byte array and xor
     * @param b1 byte array 1
     * @param b2 byte array 2
     * @return one byte array from the result of xor
     */
    private static byte[] xorBytes(byte[] b1, byte[] b2) {
        int totalLen = Math.min(b1.length, b2.length);
        byte[] result = new byte[totalLen];
        for (int i = 0; i < totalLen; i++) {
            result[i] = (byte) (b1[i] ^ b2[i]);
        }
        return result;
    }
}


