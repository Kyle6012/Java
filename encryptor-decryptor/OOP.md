
```markdown
# Object-Oriented Programming Concepts in EncryptionDecryptionGUI Code

## Overview
The provided Java code implements an Encryption and Decryption GUI application that utilizes several Object-Oriented Programming (OOP) principles. The key concepts leveraged in this implementation include **Encapsulation**, **Inheritance**, **Polymorphism**, and **Abstraction**.

## OOP Concepts

### 1. Encapsulation
Encapsulation is the bundling of data (attributes) and methods (functions) that operate on the data into a single unit called a class. This concept is used in the `EncryptionDecryptionGUI` class, where both the data (like `secretKey`, `messageField`, `resultArea`, etc.) and methods (like `encryptAES`, `decryptAES`, etc.) are encapsulated within the class.

```java
public class EncryptionDecryptionGUI extends JFrame {
    private JComboBox<String> algorithmComboBox;
    private JTextField messageField;
    private JTextArea resultArea;
    private SecretKey secretKey; // Encapsulated data
    // ...
}
```

### 2. Inheritance
Inheritance allows a class to inherit properties and methods from another class. In this code, the `EncryptionDecryptionGUI` class extends `JFrame`, which is a part of the Swing library for creating windows in Java.

```java
public class EncryptionDecryptionGUI extends JFrame {
    // The class inherits attributes and methods from JFrame
}
```

### 3. Polymorphism
Polymorphism allows objects to be treated as instances of their parent class. It enables methods to perform different functions based on the object type. The event listeners (such as `EncryptButtonListener` and `DecryptButtonListener`) can be considered examples of polymorphism. They implement the `ActionListener` interface, allowing the same method (`actionPerformed`) to behave differently depending on the context.

```java
private class EncryptButtonListener implements ActionListener {
    @Override
    public void actionPerformed(ActionEvent e) {
        // Handling the button click for encryption
    }
}
```

### 4. Abstraction
Abstraction involves hiding complex implementation details and exposing only the necessary parts of an object. This is seen in the methods defined for encryption, decryption, and hashing. Users of the `EncryptionDecryptionGUI` class need not understand how the cryptographic algorithms work; they just use the interface without needing to know the underlying complexity.

```java
private static String encryptAES(String message, SecretKey secretKey) throws Exception {
    // Encryption logic is abstracted behind this interface
    // Users simply call this method with the required parameters
}
```

## Conclusion
The `EncryptionDecryptionGUI` Java application effectively demonstrates key OOP principles such as encapsulation, inheritance, polymorphism, and abstraction. By organizing code in a structured manner, these concepts not only promote code reuse but also make it more maintainable and scalable. Understanding these OOP fundamentals is crucial for software development, especially in larger, more complex systems.
