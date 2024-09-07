import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.security.MessageDigest;
import java.util.Base64;

public class EncryptionDecryptionGUI extends JFrame {
    private JComboBox<String> algorithmComboBox;
    private JTextField messageField;
    private JTextArea resultArea;
    private SecretKey secretKey;

    // List of hashing algorithms
    private static final String[] HASH_ALGORITHMS = {"MD5", "SHA-1", "SHA-256", "SHA-512"};

    public EncryptionDecryptionGUI() {
        // Set up the frame
        setTitle("Encryption & Decryption with Hashing");
        setSize(500, 400);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new BorderLayout());

        // Top Panel for input
        JPanel topPanel = new JPanel(new GridLayout(4, 1));
        
        // Algorithm Selection
        algorithmComboBox = new JComboBox<>(HASH_ALGORITHMS);
        topPanel.add(new JLabel("Select Hashing Algorithm:"));
        topPanel.add(algorithmComboBox);

        // Message input
        messageField = new JTextField();
        topPanel.add(new JLabel("Enter the message to encrypt:"));
        topPanel.add(messageField);

        add(topPanel, BorderLayout.NORTH);

        // Result Area
        resultArea = new JTextArea();
        resultArea.setEditable(false);
        add(new JScrollPane(resultArea), BorderLayout.CENTER);

        // Bottom Panel for buttons
        JPanel bottomPanel = new JPanel();
        JButton encryptButton = new JButton("Encrypt & Hash");
        JButton decryptButton = new JButton("Decrypt");

        bottomPanel.add(encryptButton);
        bottomPanel.add(decryptButton);

        add(bottomPanel, BorderLayout.SOUTH);

        // Action listeners
        encryptButton.addActionListener(new EncryptButtonListener());
        decryptButton.addActionListener(new DecryptButtonListener());

        // Generate AES key once
        try {
            secretKey = generateAESKey();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Encrypt button action
    private class EncryptButtonListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            try {
                String message = messageField.getText();
                if (message.isEmpty()) {
                    resultArea.setText("Please enter a message.");
                    return;
                }

                // Encrypt the message using AES
                String encryptedMessage = encryptAES(message, secretKey);

                // Hash the message using the selected algorithm
                String algorithm = (String) algorithmComboBox.getSelectedItem();
                String hashedMessage = hashMessage(message, algorithm);

                // Display results
                resultArea.setText("Encrypted Message: " + encryptedMessage + "\n");
                resultArea.append("Hashed Message (" + algorithm + "): " + hashedMessage + "\n");

            } catch (Exception ex) {
                resultArea.setText("Error during encryption: " + ex.getMessage());
            }
        }
    }

    // Decrypt button action
    private class DecryptButtonListener implements ActionListener {
    @Override
    public void actionPerformed(ActionEvent e) {
        try {
            String encryptedMessage = messageField.getText();  // Assume the user enters the encrypted text to decrypt.
            if (encryptedMessage.isEmpty()) {
                resultArea.setText("Please enter an encrypted message.");
                return;
            }

            // Decrypt the message
            String decryptedMessage = decryptAES(encryptedMessage, secretKey);

            // Display the decrypted message
            resultArea.append("Decrypted Message: " + decryptedMessage + "\n");

        } catch (Exception ex) {
            resultArea.setText("Error during decryption: " + ex.getMessage());
        }
    }
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

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            EncryptionDecryptionGUI gui = new EncryptionDecryptionGUI();
            gui.setVisible(true);
        });
    }
}
