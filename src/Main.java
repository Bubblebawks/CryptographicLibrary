import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Scanner;

public class Main {
    final static Scanner scnr = new Scanner(System.in);
    public static void main(String args[]) {
        menuPrompt();
    }

    /**
     * Prompt for user to select options
     */
    public static void menuPrompt() {
        String function = "";
        String input = "";
        String output = "";

        do{
            System.out.println("Enter your desired function: " +
                    "\nH (Hash) " +
                    "\nM (MAC) " +
                    "\nE (Encrypt) " +
                    "\nD (Decrypt) " +
                    "\nQ (Quit)");
            function = scnr.nextLine();

            switch (function) {

                /**
                 * Hash
                 */
                case "H", "h" -> {
                    System.out.println("Would you like to input a: \nF (file) \nT (text) ");
                    input = scnr.nextLine();

                    System.out.println("Would you like to output a: \nF (file) \nT (text) ");
                    output = scnr.nextLine();

                    byte[] data = getData(input);
                    byte[] crypt = hash(data);

                    if (output == "F" || output == "f") {
                        System.out.println("Enter folder path:");
                        String folderPath = scnr.nextLine();
                        outputFile(folderPath + "\\Hash.txt", crypt);
                    } else {
                        printByte(crypt);
                    }
                }
                /**
                 * MAC
                 */
                case "M", "m" -> {
                    System.out.println("MAC under construction");
                }
                /**
                 * Encrypt
                 */
                case "E", "e" -> {
                    System.out.println("Encrypting under construction");
                }
                /**
                 * Decrypt
                 */
                case "D", "d" -> {
                    System.out.println("Decrypting under construction");
                }
                /**
                 * Exit menu and stop running
                 */
                case "Q", "q" -> {System.out.println("Closing menu");}

                default -> System.out.println("Invalid option(s) has been selected.");

            }
        } while (!function.equalsIgnoreCase("q") || !function.equalsIgnoreCase("Q"));
        scnr.close();
    }

    /**
     * Asks user to enter file or text
     * @param inputMethod
     * @return
     */
    private static byte[] getData(String inputMethod) {
        String out = "";
        if (inputMethod.equals("F") || inputMethod.equals("f")) {
            return readFile();
        } else if(inputMethod.equals("T") || inputMethod.equals("t")){
            System.out.println("Please enter data:");
            out =  scnr.nextLine();
            return out.getBytes();
        }
        return null;
    }

    /**
     * Read from file that user provided
     * @return
     */
    private static byte[] readFile() {
        System.out.print("Enter file path: ");
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
     * Create an output file
     * @param filePath
     * @param data
     */
    private static void outputFile(String filePath, byte[] data) {
        try (FileOutputStream outputStream = new FileOutputStream(filePath)) {
            outputStream.write(data);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Print the result of given input in byte form
     * @param data
     */
    private static void printByte(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < data.length; i++) {
            sb.append(" ").append(byteToString(data[i]));
        }
        System.out.println("Result:" + sb.toString());
    }

    /**
     * Turns byte into string
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

    private static final KMACXOF256 SPONGE = new KMACXOF256(new byte[0], new byte[0], 512, "D" );
    /*
    private static byte[] hash(byte[] data) {
        SPONGE.sha3_update(data);
        return SPONGE.sha3_final();
    }

    private static byte[] hash(byte[] data) {
        SPONGE.sha3_update(data);
        return SPONGE.retrieveData();
    }
     */
    private static byte[] hash(byte[] data) {
        String K = "";
        KMACXOF256 sponge = new KMACXOF256(K.getBytes(), data, 512, "D");
        return sponge.retrieveData();
    }
}