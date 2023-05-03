import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.security.MessageDigest;
import java.util.Arrays;
public class MAC {

    public static void first (String[] args) throws Exception {
        // Define the file and passphrase
        File file = new File("/path/to/file");
        String passphrase = "myPassphrase";

        // Generate a secret key from the passphrase
        SecretKey secretKey = generateSecretKey(passphrase);

        // Compute the MAC of the file using HMAC-SHA256
        byte[] mac = computeMac(file, secretKey, "HmacSHA256");

        // Print the MAC as a hexadecimal string
        System.out.println(bytesToHex(mac));
    }

    private static SecretKey generateSecretKey(String passphrase) throws Exception {
        // Generate a 256-bit key from the passphrase using SHA-256
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = digest.digest(passphrase.getBytes("UTF-8"));

        // Use the key bytes to create a secret key
        return new SecretKeySpec(keyBytes, "AES");
    }

    private static byte[] computeMac(File file, SecretKey secretKey, String algorithm) throws Exception {
        // Initialize a MAC object with the secret key and algorithm
        Mac mac = Mac.getInstance(algorithm);
        mac.init(secretKey);

        // Read the file data into a byte array
        byte[] fileData = new byte[(int) file.length()];
        try (FileInputStream fis = new FileInputStream(file)) {
            fis.read(fileData);
        }

        // Compute the MAC of the file data
        return mac.doFinal(fileData);
    }

    // Utility method to convert a byte array to a hexadecimal string
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }


}
