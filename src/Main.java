import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Scanner;

public class Main {
    final static Scanner scnr = new Scanner(System.in);
    public static void main(String args[]) {
        System.out.println("Enter your desired function: \nH (hash) " +
                "\nM (MAC) \nE (Encrypt) \nD (Decrypt) ");
        String function = scnr.nextLine();
        System.out.println("Would you like to input a: \nF (file) \nT (text) ");
        String input = scnr.nextLine();
        System.out.println("Would you like to output a: \nF (file) \nT (text) ");
        String output = scnr.nextLine();
        switch (function) {
            case "H":
            case "h":
                byte[] data = getData(input);
                byte[] crypt = hash(data);
                if (output == "F" || output == "f") {
                    System.out.println("Enter folder path:");
                    String folderPath = scnr.nextLine();
                    outputFile(folderPath + "\\Hash.txt", crypt);
                } else {
                    printByte(crypt);
                }
                break;
            default:
                System.out.println("Invalid option(s) has been selected.");
                break;
        }
    }

    //asks user to enter file or text
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

    //read from file that user provided
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

    //create an output file
    private static void outputFile(String filePath, byte[] data) {
        try (FileOutputStream outputStream = new FileOutputStream(filePath)) {
            outputStream.write(data);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    //print the result of given input in byte form
    private static void printByte(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < data.length; i++) {
            sb.append(" ").append(byteToString(data[i]));
        }
        System.out.println("Result:" + sb.toString());
    }

    //turns byte into string
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