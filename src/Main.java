/*
Vivian Tran, Gil Rabara, Andrew John Nguyen
TCSS 487 Cryptography Project (Part 1) - Main
5/7/2023
 */

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Scanner;

public class Main {
    final static Scanner scnr = new Scanner(System.in);
    public static void main(String[] args) {
        System.out.print("""
                Enter your desired function:\s
                H (hash)\s
                M (MAC)\s
                E (Encrypt)\s
                D (Decrypt)
                Q (Quit)\s
                >>\s""");
        String function = scnr.nextLine();
        while(!function.equalsIgnoreCase("Q")) {
        System.out.print("Would you like to input a: \nF (file) \nT (text)\n>> ");
        String input = scnr.nextLine();
        System.out.print("Would you like to output a: \nF (file) \nT (text)\n>> ");
        String output = scnr.nextLine();

            switch (function) {
                case "t" -> printTestVector();
                case "H", "h" -> {
                    byte[] data = getData(input);
                    byte[] crypto = hash("".getBytes(), data);
                    if (output.equalsIgnoreCase("f")) {
                        System.out.println("Enter output folder path:");
                        String folderPath = scnr.nextLine();
                        outputFile(folderPath + "\\Hash.txt", convertBytesToHex(crypto));
                    } else {
                        System.out.println("The hash of your text is: \n" + convertBytesToHex(crypto) + "\n");
                    }
                }
                case "M", "m" -> {
                    byte[] key = getKey(input);
                    byte[] data1 = getData(input);
                    byte[] crypto1 = MAC(key, data1);
                    if (output.equalsIgnoreCase("f")) {
                        System.out.println("Enter output folder path:");
                        String folderPath = scnr.nextLine();
                        outputFile(folderPath + "\\MAC.txt", convertBytesToHex(crypto1));
                    } else {
                        System.out.println("The MAC of your text is: \n" + convertBytesToHex(crypto1) + "\n");
                    }
                }
                case "E", "e" -> {
                    byte[] key1 = getKey(input);
                    byte[] data2 = getData(input);
                    encrypt(key1, data2, output);
                }
                case "D", "d" -> {
                    byte[] crypto2 = getData(input);
                    byte[] key2 = getKey(input);
                    assert crypto2 != null;
                    decrypt(key2, hexStringToByteArray(new String(crypto2, StandardCharsets.UTF_8)), output);
                }
                default -> System.out.println("Invalid mode selected.\n>>>>>>>>>> EXITING PROGRAM <<<<<<<<<<<");
            }
            System.out.print("""
                    Enter your desired function:\s
                    H (hash)\s
                    M (MAC)\s
                    E (Encrypt)\s
                    D (Decrypt)
                    Q (Quit)\s
                    >>\s""");
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
        if (input.equalsIgnoreCase("F")) {
            return readFile();
        } else if(input.equalsIgnoreCase("T")){
            System.out.print("Enter text: \n>> ");
            String out =  scnr.nextLine();
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
            return fileInput.readAllBytes();
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
     * hashes given data based on key
     * @param key passphrase or password given from user
     * @param data the text or text from file given from user
     * @return hashed value of data
     */
    private static byte[] hash(byte[] key, byte[] data) {
        KMACXOF256 sponge = new KMACXOF256(key, data, 512, "D");
        return sponge.retrieveData();
    }
    /**
     * authentication tag under passphrase
     * @param key passphrase or password given from user
     * @param data the text or text from file given from user
     * @return hashed value of data
     */
    private static byte[] MAC(byte[] key, byte[] data) {
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
                return fileInput.readAllBytes();
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
        // getting a random 512 bit value (z)
        SecureRandom secureRandom = new SecureRandom();
        byte[] z = new byte[64];
        secureRandom.nextBytes(z);

        // calculate ke and ka
        byte[] keccak = (new KMACXOF256(addBytes(z, key), new byte[0], 1024, "S")).retrieveData();
        byte[] ke = Arrays.copyOfRange(keccak, 0, keccak.length / 2);
        byte[] ka = Arrays.copyOfRange(keccak, keccak.length / 2, keccak.length);

        // encrypted message
        byte[] c = xorBytes((new KMACXOF256(ke, new byte[0], data.length * 8, "SKE")).retrieveData(), data);
        // MAC
        byte[] t = (new KMACXOF256(ka, data, 512, "SKA")).retrieveData();

        // Populate the cryptogram: cryptogram = (z | c | t)
        ByteBuffer bb = ByteBuffer.allocate(z.length + c.length + t.length)
                .put(z).put(c).put(t);
        byte[] cryptogram = bb.array();

        if (output.equalsIgnoreCase("F")) {
            System.out.println("Enter folder path:");
            String folderPath = scnr.nextLine();
            outputFile(folderPath + "\\cryptogram.txt", convertBytesToHex(cryptogram));
        } else {
            System.out.println("The encryption of your text is: \n" + convertBytesToHex(cryptogram) + "\n");
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

        // decrypt the message
        byte[] m = xorBytes((new KMACXOF256(ke, new byte[0], c.length * 8, "SKE")).retrieveData(), c);
        byte[] t_prime = (new KMACXOF256(ka, m, 512, "SKA")).retrieveData();

        if (!Arrays.equals(t, t_prime)) {
            System.out.println("MAC verification failed. The message may have been tampered with, or key is incorrect.");
            return;
        }

        if (output.equalsIgnoreCase("F")) {
            System.out.println("Enter folder path:");
            String folderPath = scnr.nextLine();
            outputFile(folderPath + "\\message.txt", new String(m, StandardCharsets.UTF_8));
        } else {
            System.out.println("The decryption of your text is: \n" + new String(m, StandardCharsets.UTF_8) + "\n");
        }
    }

    /**
     * converts hexadecimal to byte array
     * @param hex string input from user
     * @return byte array conversion of hex string given
     */
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


