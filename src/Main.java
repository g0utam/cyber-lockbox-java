import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.File;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Arrays;

public class Main {
    private static final int SALT_LEN = 16;
    private static final int IV_LEN = 12;
    private static final int TAG_LEN_BYTES = 16;
    private static final int PBKDF2_ITERATIONS = 480000;
    private static final int KEY_LEN_BITS = 256;

    private JFrame frame;
    private JTextField txtFile;
    private JTextField txtOutput;
    private JPasswordField txtPassword;

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (Exception ignored) {}
            new Main().createAndShowGUI();
        });
    }

    private void createAndShowGUI() {
        frame = new JFrame("🔐 Cyber Lockbox Pro - Java (Swing)");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(540, 360);
        frame.setResizable(false);
        frame.setLocationRelativeTo(null);

        JPanel root = new JPanel();
        root.setBackground(new Color(30, 30, 30));
        root.setLayout(new BorderLayout(10,10));
        frame.setContentPane(root);

        JLabel title = new JLabel("CYBER LOCKBOX PRO", SwingConstants.CENTER);
        title.setFont(new Font("Arial", Font.BOLD, 20));
        title.setForeground(new Color(0, 230, 172));
        title.setBorder(BorderFactory.createEmptyBorder(10,0,0,0));
        root.add(title, BorderLayout.NORTH);

        JPanel center = new JPanel(new GridBagLayout());
        center.setOpaque(false);
        root.add(center, BorderLayout.CENTER);

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(8,8,8,8);
        gbc.anchor = GridBagConstraints.WEST;

        gbc.gridx = 0; gbc.gridy = 0;
        JLabel lblFile = new JLabel("Select File:");
        lblFile.setForeground(Color.WHITE);
        center.add(lblFile, gbc);

        txtFile = new JTextField(28);
        gbc.gridx = 1; gbc.gridy = 0;
        center.add(txtFile, gbc);

        JButton btnBrowse = new JButton("Browse");
        btnBrowse.addActionListener(this::onBrowse);
        gbc.gridx = 2; gbc.gridy = 0;
        center.add(btnBrowse, gbc);

        gbc.gridx = 0; gbc.gridy = 1;
        JLabel lblOut = new JLabel("Output Name:");
        lblOut.setForeground(Color.WHITE);
        center.add(lblOut, gbc);

        txtOutput = new JTextField(28);
        gbc.gridx = 1; gbc.gridy = 1;
        center.add(txtOutput, gbc);

        gbc.gridx = 0; gbc.gridy = 2;
        JLabel lblPass = new JLabel("Password:");
        lblPass.setForeground(Color.WHITE);
        center.add(lblPass, gbc);

        txtPassword = new JPasswordField(28);
        gbc.gridx = 1; gbc.gridy = 2;
        center.add(txtPassword, gbc);

        JPanel btnPanel = new JPanel();
        btnPanel.setOpaque(false);
        JButton btnEncrypt = new JButton("🔒 Encrypt");
        btnEncrypt.setPreferredSize(new Dimension(140, 30));
        btnEncrypt.addActionListener(e -> process("encrypt"));

        JButton btnDecrypt = new JButton("🔓 Decrypt");
        btnDecrypt.setPreferredSize(new Dimension(140, 30));
        btnDecrypt.addActionListener(e -> process("decrypt"));

        btnPanel.add(btnEncrypt);
        btnPanel.add(btnDecrypt);

        gbc.gridx = 0; gbc.gridy = 3;
        gbc.gridwidth = 3;
        gbc.anchor = GridBagConstraints.CENTER;
        center.add(btnPanel, gbc);

        JLabel footer = new JLabel("Developed by g0utam | AES-256 Secure", SwingConstants.CENTER);
        footer.setForeground(Color.LIGHT_GRAY);
        footer.setBorder(BorderFactory.createEmptyBorder(8,0,8,0));
        root.add(footer, BorderLayout.SOUTH);

        frame.setVisible(true);
    }

    private void onBrowse(ActionEvent ev) {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        int res = chooser.showOpenDialog(frame);
        if (res == JFileChooser.APPROVE_OPTION) {
            File f = chooser.getSelectedFile();
            txtFile.setText(f.getAbsolutePath());
        }
    }

    private void process(String action) {
        String filePath = txtFile.getText().trim();
        String outputName = txtOutput.getText().trim();
        char[] password = txtPassword.getPassword();

        if (filePath.isEmpty() || outputName.isEmpty() || password.length == 0) {
            JOptionPane.showMessageDialog(frame, "Please fill all fields.", "Missing Info", JOptionPane.WARNING_MESSAGE);
            return;
        }

        try {
            File inputFile = new File(filePath);
            if (!inputFile.exists()) {
                JOptionPane.showMessageDialog(frame, "Selected file does not exist.", "File Error", JOptionPane.ERROR_MESSAGE);
                return;
            }

            if ("encrypt".equals(action)) {
                File out = encryptFile(inputFile, outputName, password);
                JOptionPane.showMessageDialog(frame,
                        "File encrypted successfully!\nSaved as:\n" + out.getAbsolutePath(),
                        "Success", JOptionPane.INFORMATION_MESSAGE);
            } else {
                File out = decryptFile(inputFile, outputName, password);
                JOptionPane.showMessageDialog(frame,
                        "File decrypted successfully!\nSaved as:\n" + out.getAbsolutePath(),
                        "Success", JOptionPane.INFORMATION_MESSAGE);
            }

            txtFile.setText("");
            txtOutput.setText("");
            Arrays.fill(password, '\0');
            txtPassword.setText("");

        } catch (Exception ex) {
            Arrays.fill(password, '\0');
            txtPassword.setText("");
            JOptionPane.showMessageDialog(frame, "Operation failed!\n" + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            ex.printStackTrace();
        }
    }

    private static File encryptFile(File inputFile, String outputName, char[] password) throws Exception {
        byte[] salt = new byte[SALT_LEN];
        SecureRandom rnd = new SecureRandom();
        rnd.nextBytes(salt);
        byte[] iv = new byte[IV_LEN];
        rnd.nextBytes(iv);
        SecretKey key = deriveKey(password, salt);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LEN_BYTES * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        byte[] plaintext = Files.readAllBytes(inputFile.toPath());
        byte[] cipherAndTag = cipher.doFinal(plaintext);

        int tagOffset = cipherAndTag.length - TAG_LEN_BYTES;
        byte[] ciphertext = Arrays.copyOfRange(cipherAndTag, 0, tagOffset);
        byte[] tag = Arrays.copyOfRange(cipherAndTag, tagOffset, cipherAndTag.length);

        byte[] outBytes = new byte[SALT_LEN + IV_LEN + TAG_LEN_BYTES + ciphertext.length];
        int pos = 0;
        System.arraycopy(salt, 0, outBytes, pos, SALT_LEN); pos += SALT_LEN;
        System.arraycopy(iv, 0, outBytes, pos, IV_LEN); pos += IV_LEN;
        System.arraycopy(tag, 0, outBytes, pos, TAG_LEN_BYTES); pos += TAG_LEN_BYTES;
        System.arraycopy(ciphertext, 0, outBytes, pos, ciphertext.length);

        File folder = inputFile.getParentFile();
        File outputFile = new File(folder, outputName + ".enc");
        Files.write(outputFile.toPath(), outBytes);
        return outputFile;
    }

    private static File decryptFile(File inputFile, String outputName, char[] password) throws Exception {
        byte[] all = Files.readAllBytes(inputFile.toPath());
        int pos = 0;
        byte[] salt = Arrays.copyOfRange(all, pos, pos + SALT_LEN); pos += SALT_LEN;
        byte[] iv = Arrays.copyOfRange(all, pos, pos + IV_LEN); pos += IV_LEN;
        byte[] tag = Arrays.copyOfRange(all, pos, pos + TAG_LEN_BYTES); pos += TAG_LEN_BYTES;
        byte[] ciphertext = Arrays.copyOfRange(all, pos, all.length);

        byte[] cipherAndTag = new byte[ciphertext.length + tag.length];
        System.arraycopy(ciphertext, 0, cipherAndTag, 0, ciphertext.length);
        System.arraycopy(tag, 0, cipherAndTag, ciphertext.length, tag.length);

        SecretKey key = deriveKey(password, salt);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LEN_BYTES * 8, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        byte[] plaintext = cipher.doFinal(cipherAndTag);

        File folder = inputFile.getParentFile();
        File outputFile = new File(folder, outputName + ".txt");
        Files.write(outputFile.toPath(), plaintext);
        return outputFile;
    }

    private static SecretKey deriveKey(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, KEY_LEN_BITS);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = skf.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }
}
