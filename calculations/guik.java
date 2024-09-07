import javax.swing.*;
import java.awt.*;

public class gui {
    static int r;
    static double area;
    static double volume;
    static int h;
    static int choice;

    public static void main(String[] args) {
        String radiusInput = JOptionPane.showInputDialog(null, "Enter radius:");
        r = Integer.parseInt(radiusInput);
        String heightInput = JOptionPane.showInputDialog(null, "Enter height:");
        h = Integer.parseInt(heightInput);
        String[] options = {"Surface Area of an open Cylinder", "Surface Area of a closed Cylinder", "Volume of the cylinder", "Exit"};
        choice = JOptionPane.showOptionDialog(null, "Select an action:",
                "Cylinder Calculator", JOptionPane.DEFAULT_OPTION, JOptionPane.INFORMATION_MESSAGE, null, options, options[0]);

        switch (choice) {
            case 0 -> open();
            case 1 -> closed();
            case 2 -> vol();
            case 3 -> JOptionPane.showMessageDialog(null, "Exiting...", "Exit", JOptionPane.INFORMATION_MESSAGE);
        }

        System.exit(0);
    }

    static void vol() {
        volume = 3.142 * r * r * h;
        displayResult("The Volume is: " + volume);
    }

    static void open() {
        if (r > h) {
            area = 3.142 * r * (h + r);
            displayResult("The surface area is: " + area);
        } else {
            JOptionPane.showMessageDialog(null, "The radius is less than height. Volume will be calculated.", "Info", JOptionPane.INFORMATION_MESSAGE);
            vol();
        }
    }

    static void closed() {
        area = 2 * 3.142 * r * (h + r);
        displayResult("The surface area is: " + area);
    }

    static void displayResult(String result) {
        JPanel panel = new JPanel();
        JLabel label = new JLabel(result);
        panel.add(label);
        JOptionPane.showMessageDialog(null, panel, "Result", JOptionPane.INFORMATION_MESSAGE);
    }
}
