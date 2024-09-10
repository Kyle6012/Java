import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class SimpleLogin {
    public static void main(String[] args) {
        // Create the frame
        JFrame frame = new JFrame("Login System");
        frame.setSize(350, 200);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setLayout(null);

        // Create user label
        JLabel userLabel = new JLabel("Username:");
        userLabel.setBounds(50, 30, 80, 25);
        frame.add(userLabel);

        // Create user text field
        JTextField userText = new JTextField(20);
        userText.setBounds(140, 30, 150, 25);
        frame.add(userText);

        // Create password label
        JLabel passwordLabel = new JLabel("Password:");
        passwordLabel.setBounds(50, 70, 80, 25);
        frame.add(passwordLabel);

        // Create password field
        JPasswordField passwordText = new JPasswordField(20);
        passwordText.setBounds(140, 70, 150, 25);
        frame.add(passwordText);

        // Create login button
        JButton loginButton = new JButton("Login");
        loginButton.setBounds(140, 110, 80, 25);
        frame.add(loginButton);

        // Create a label to display the login status
        JLabel statusLabel = new JLabel("");
        statusLabel.setBounds(50, 140, 250, 25);
        frame.add(statusLabel);

        // Add action listener to the login button
        loginButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String username = userText.getText();
                String password = new String(passwordText.getPassword());

                // Simple authentication check
                if ("admin".equals(username) && "password123".equals(password)) {
                    statusLabel.setText("Login successful!");
                } else {
                    statusLabel.setText("Login failed! Incorrect username or password.");
                }
            }
        });

        // Set frame visibility
        frame.setVisible(true);
    }
          }
