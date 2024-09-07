# Java Encryption & Decryption Program with GUI

## Overview

This project demonstrates a simple Java application that allows a user to:
- Encrypt a message using the **AES** encryption algorithm.
- Hash the message using a choice of **4 hashing algorithms**: `MD5`, `SHA-1`, `SHA-256`, or `SHA-512`.
- Decrypt the message to its original form.

This program uses **Swing**, a Java GUI framework, to build a graphical interface that users can interact with. The program provides the user with a text input to enter their message, buttons to perform encryption, hashing, and decryption, and a display area to show the results.

## Features
- **AES Encryption**: Uses the AES (Advanced Encryption Standard) to securely encrypt the user's message.
- **Hashing**: Supports four popular hashing algorithms:
  - MD5
  - SHA-1
  - SHA-256
  - SHA-512
- **Decryption**: Allows the encrypted message to be decrypted back to its original form.

## How It Works

### 1. User Interface (GUI)

The program opens a graphical window where the user can:
- Select a hashing algorithm from a dropdown menu.
- Enter a message into a text field.
- Click a button to **encrypt and hash** the message.
- Click another button to **decrypt** the message.

### 2. Algorithms Used

- **AES (Advanced Encryption Standard)**: AES is a widely used encryption algorithm that converts plaintext into a secure, unreadable format. In this program, we use a 128-bit AES key to encrypt the user's message.
  
- **Hashing Algorithms**: The program supports several hashing algorithms that convert the input message into a fixed-length hash value:
  - **MD5**: Produces a 128-bit hash, commonly used but considered insecure for modern applications.
  - **SHA-1**: Produces a 160-bit hash, more secure than MD5 but now vulnerable to certain types of attacks.
  - **SHA-256**: Produces a 256-bit hash, a strong and secure option.
  - **SHA-512**: Produces a 512-bit hash, the most secure option available in this program.

### 3. GUI Components

- **JFrame**: The main window of the application.
- **JTextField**: Used for user input (to enter the message for encryption).
- **JComboBox**: A dropdown list for selecting the hashing algorithm.
- **JButton**: Two buttons – one for encrypting and hashing the message, and another for decrypting it.
- **JTextArea**: Displays the results, including the encrypted message, hash, and decrypted message.

## Code Explanation

### 1. Importing Libraries

```java
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
```

- **javax.crypto** : Contains classes and interfaces for encryption and decryption.
- **javax.swing** : Provides the components for creating a GUI (e.g., windows, buttons, text fields).
- **java.security.MessageDigest** : Allows us to use different hashing algorithms (MD5, SHA-1, etc.).
- **Base64** : Encodes and decodes data using Base64, making binary data readable

### 2. Creating the Main Window(JFrame)

```java
public class EncryptionDecryptionGUI extends JFrame {
    private JComboBox<String> algorithmComboBox;
    private JTextField messageField;
    private JTextArea resultArea;
    private SecretKey secretKey;

```
We extend the JFrame class to create the main window for our application.

- **JComboBox**: A dropdown menu for selecting the hashing algorithm.
- **JTextField**: A text box for the user to input the message.
- **JTextArea**: A large, non-editable text box where the results are displayed.
- **SecretKey**: The secret AES key for encryption and decryption.

### 3. GUI setup

```java
JPanel topPanel = new JPanel(new GridLayout(4, 1));
algorithmComboBox = new JComboBox<>(HASH_ALGORITHMS);
topPanel.add(new JLabel("Select Hashing Algorithm:"));
topPanel.add(algorithmComboBox);

messageField = new JTextField();
topPanel.add(new JLabel("Enter the message to encrypt:"));
topPanel.add(messageField);
add(topPanel, BorderLayout.NORTH);

resultArea = new JTextArea();
resultArea.setEditable(false);
add(new JScrollPane(resultArea), BorderLayout.CENTER);

JPanel bottomPanel = new JPanel();
JButton encryptButton = new JButton("Encrypt & Hash");
JButton decryptButton = new JButton("Decrypt");
bottomPanel.add(encryptButton);
bottomPanel.add(decryptButton);
add(bottomPanel, BorderLayout.SOUTH);

```
Here, we create the components and layout for the GUI. The frame is divided into three sections:

- **Top panel**: Dropdown for algorithm selection and input field for the message.
- **Center**: A scrollable text area to display results.
- **Bottom panel**: Buttons for "Encrypt & Hash" and "Decrypt".

### 4. Encryption/Hash functionality

```java
private class EncryptButtonListener implements ActionListener {
    @Override
    public void actionPerformed(ActionEvent e) {
        try {
            String message = messageField.getText();
            String encryptedMessage = encryptAES(message, secretKey);
            String algorithm = (String) algorithmComboBox.getSelectedItem();
            String hashedMessage = hashMessage(message, algorithm);

            resultArea.setText("Encrypted Message: " + encryptedMessage + "\n");
            resultArea.append("Hashed Message (" + algorithm + "): " + hashedMessage + "\n");

        } catch (Exception ex) {
            resultArea.setText("Error during encryption: " + ex.getMessage());
        }
    }
}

```

- **Encrypt**: The message is encrypted using AES.
- **Hash**: The selected algorithm is used to hash the message.

### 5. Decryption functionality
```java
private class DecryptButtonListener implements ActionListener {
    @Override
    public void actionPerformed(ActionEvent e) {
        try {
            String message = messageField.getText();
            String encryptedMessage = encryptAES(message, secretKey);
            String decryptedMessage = decryptAES(encryptedMessage, secretKey);

            resultArea.append("Decrypted Message: " + decryptedMessage + "\n");

        } catch (Exception ex) {
            resultArea.setText("Error during decryption: " + ex.getMessage());
        }
    }
}

```
The decryption logic is triggered when the user clicks the "Decrypt" button.

### 6. AES Encryption/Decryption methods

```java
private static String encryptAES(String message, SecretKey secretKey) throws Exception {
    Cipher cipher = Cipher.getInstance("AES");
    cipher.init(Cipher.ENCRYPT_MODE, secretKey);
    byte[] encryptedBytes = cipher.doFinal(message.getBytes());
    return Base64.getEncoder().encodeToString(encryptedBytes);
}

private static String decryptAES(String encryptedMessage, SecretKey secretKey) throws Exception {
    Cipher cipher = Cipher.getInstance("AES");
    cipher.init(Cipher.DECRYPT_MODE, secretKey);
    byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
    return new String(decryptedBytes);
}

```
AES (Advanced Encryption Standard) is a symmetric encryption algorithm that uses the same key for both encryption and decryption. This section explains how AES encryption and decryption are implemented in the provided Java code.

The *encryptAES* method encrypts a plaintext message using AES. Here’s how it works:

```java
private static String encryptAES(String message, SecretKey secretKey) throws Exception {
    Cipher cipher = Cipher.getInstance("AES");           // Create a Cipher instance for AES
    cipher.init(Cipher.ENCRYPT_MODE, secretKey);          // Initialize the cipher in ENCRYPT_MODE with the secret key
    byte[] encryptedBytes = cipher.doFinal(message.getBytes()); // Encrypt the message bytes
    return Base64.getEncoder().encodeToString(encryptedBytes); // Encode the encrypted bytes to Base64 for readable format
}

```
- **Cipher.getInstance("AES")**: This creates a Cipher instance configured to use the AES encryption algorithm.
- **cipher.init(Cipher.ENCRYPT_MODE, secretKey)**: Initializes the cipher to encryption mode with the specified secret key.
- **cipher.doFinal(message.getBytes())**: Encrypts the message bytes.
- **Base64.getEncoder().encodeToString(encryptedBytes)**: Encodes the encrypted byte array into a Base64 string for easier display and transmission.

The *decryptAES* method decrypts an AES-encrypted message. Here’s the implementation:

```java
private static String decryptAES(String encryptedMessage, SecretKey secretKey) throws Exception {
    Cipher cipher = Cipher.getInstance("AES");           // Create a Cipher instance for AES
    cipher.init(Cipher.DECRYPT_MODE, secretKey);          // Initialize the cipher in DECRYPT_MODE with the secret key
    byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage)); // Decode Base64 and decrypt
    return new String(decryptedBytes);                     // Convert decrypted bytes to a string
}

```
- **Cipher.getInstance("AES")**: Creates a Cipher instance configured to use AES.
- **cipher.init(Cipher.DECRYPT_MODE, secretKey)**: Initializes the cipher to decryption mode with the specified secret key.
- **Base64.getDecoder().decode(encryptedMessage)**: Decodes the Base64-encoded encrypted message into bytes.
- **cipher.doFinal(decodedBytes)**: Decrypts the byte array.
- **new String(decryptedBytes)**: Converts the decrypted byte array back into a string.

#### Generating a secret key

The secret key used for AES encryption and decryption is generated using the KeyGenerator class:

```java
private static SecretKey generateSecretKey() throws Exception {
    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
    keyGenerator.init(128); // Key size of 128 bits
    return keyGenerator.generateKey(); // Generate and return the secret key
}

```
- **KeyGenerator.getInstance("AES")**: Creates a KeyGenerator instance for AES.
- **keyGenerator.init(128)**: Initializes the key generator to use a key size of 128 bits.
- **keyGenerator.generateKey()**: Generates and returns the AES secret key.

The *generateSecretKey* method is essential for creating a key that both encryption and decryption functions use.

#### Base64 Coding and encoding

Base64 encoding and decoding are used to handle binary data in a text format, making it suitable for display and transmission:

**Encoding**: Converts binary data (encrypted bytes) into a Base64 string.
**Decoding**: Converts Base64 strings back into binary data (encrypted bytes) for decryption.

```java
Base64.getEncoder().encodeToString(encryptedBytes); // Encoding
Base64.getDecoder().decode(encryptedMessage);        // Decoding

```
- **Base64.getEncoder().encodeToString(encryptedBytes)**: Encodes byte array to Base64 string.
- **Base64.getDecoder().decode(encryptedMessage)**: Decodes Base64 string to byte array.
	
