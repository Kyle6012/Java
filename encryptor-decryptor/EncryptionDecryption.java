import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Scanner;

public class EncryptionDecryption {
    // List of hashing algorithms
    private static final String[] HASH_ALGORITHMS = {"MD5", "SHA-1", "SHA-256", "SHA-512"};

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);

        // Choose a hashing algorithm
        System.out.println("Choose a hashing algorithm:");
        for (int i = 0; i < HASH_ALGORITHMS.length; i++) {
            System.out.println((i + 1) + ": " + HASH_ALGORITHMS[i]);
        }

        int choice = scanner.nextInt();
        scanner.nextLine();  // Consume the newline character

        if (choice < 1 || choice > HASH_ALGORITHMS.length) {
            System.out.println("Invalid choice.");
            return;
        }
        String chosenHashAlgorithm = HASH_ALGORITHMS[choice - 1];
        System.out.println("You chose: " + chosenHashAlgorithm);

        // Input the message
        System.out.println("Enter the message to encrypt:");
        String message = scanner.nextLine();

        // Encrypt the message using AES
        SecretKey secretKey = generateAESKey();
        String encryptedMessage = encryptAES(message, secretKey);
        System.out.println("Encrypted Message: " + encryptedMessage);

        // Hash the message
        String hashedMessage = hashMessage(message, chosenHashAlgorithm);
        System.out.println("Hashed Message (" + chosenHashAlgorithm + "): " + hashedMessage);

        // Decrypt the message
        String decryptedMessage = decryptAES(encryptedMessage, secretKey);
        System.out.println("Decrypted Message: " + decryptedMessage);
    }

    // AES Key generation
    private static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128); // AES-128 key size
        return keyGenerator.generateKey();
    }

    // AES encryption
    private static String encryptAES(String message, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // AES decryption
    private static String decryptAES(String encryptedMessage, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decryptedBytes);
    }

    // Hash the message using the selected algorithm
    private static String hashMessage(String message, String algorithm) throws Exception {
        MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
        byte[] hashBytes = messageDigest.digest(message.getBytes());
        return bytesToHex(hashBytes);
    }

    // Convert byte array to hex string
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }
}
