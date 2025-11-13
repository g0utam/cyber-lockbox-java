# 🔐 Cyber Lockbox Pro (Java Swing Edition)

Cyber Lockbox Pro is a lightweight, offline desktop tool that securely encrypts and decrypts files using **AES-256 (GCM mode)** encryption.  
It’s built entirely with **Java Swing**, featuring a clean, dark-themed interface for a simple and secure user experience.

---

## 🧩 Overview

Cyber Lockbox Pro helps protect sensitive data with modern encryption techniques.  
The application lets you:

- 🔒 **Encrypt any file** with a password you choose  
- 🔓 **Decrypt encrypted files** back to their original state  
- 🧂 Use a new **random salt and IV** each time for security  
- 💾 Perform all operations **locally**, without an internet connection  

---

## ⚙️ Technical Details

| Feature | Implementation |
|----------|----------------|
| **Encryption Algorithm** | AES-256 (GCM Mode, No Padding) |
| **Key Derivation** | PBKDF2WithHmacSHA256 (480,000 iterations) |
| **Randomization** | 16-byte Salt + 12-byte IV per encryption |
| **Authentication Tag** | 16 bytes (128-bit GCM tag) |
| **Output File Format** | `salt (16B)` → `iv (12B)` → `tag (16B)` → `ciphertext` |
| **GUI Framework** | Java Swing |
| **Minimum Java Version** | Java 11+ |

This Java version is **fully compatible** with the original Python implementation — files encrypted with one can be decrypted with the other.

---

## 🖥️ User Interface

The UI is designed for simplicity and clarity:

- A **file browser** to select your target file  
- Fields for **output file name** and **password**  
- **Encrypt** and **Decrypt** buttons for quick actions  
- Pop-up dialogs for success and error messages  
- A **dark color scheme** for a modern look and reduced eye strain  

Sensitive information like passwords is cleared from memory after each operation.

---

## 🚀 Getting Started

### 1. Clone or Download the Project

```bash
git clone https://github.com/<your-username>/cyber-lockbox-java.git
cd cyber-lockbox-java
```

### 2. Compile the Source Code

```bash
javac -d out src/Main.java
```

### 3. Run the Application

```bash
java -cp out Main
```

### 4. Using the App

1. Click **Browse** to select a file.  
2. Enter an **output name** (no extension needed).  
3. Type a **password** (used for encryption/decryption).  
4. Click **Encrypt** or **Decrypt**.  
5. The processed file will appear in the same folder.

---

## 🧠 How Encryption Works

Each time you encrypt a file:
1. A **256-bit key** is derived from your password using PBKDF2WithHmacSHA256.  
2. A new **random salt** (16 bytes) and **IV** (12 bytes) are generated.  
3. The file is encrypted with **AES-256-GCM**, which provides both confidentiality and integrity.  
4. The resulting `.enc` file is saved with the structure:
   ```
   [salt][iv][tag][ciphertext]
   ```

During decryption:
- The program extracts the salt, IV, and authentication tag.  
- The same password is used to derive the original key.  
- AES-GCM validates data integrity before decrypting the file.

---

## 🧰 Project Goals

This project was built to:
- Demonstrate practical use of **Java’s cryptography architecture (JCA)**.  
- Build a secure, real-world desktop app using **Swing**.  
- Showcase knowledge of **key derivation** and **authenticated encryption**.  
- Provide a clean, functional example suitable for portfolio presentation.

---

## ⚠️ Security Notes

- Passwords are **never stored** and are cleared from memory after use.  
- Each encryption uses a unique salt and IV for better security.  
- AES-GCM ensures both **data confidentiality** and **authenticity**.  
- Always keep your password safe — if it’s lost, the encrypted file cannot be recovered.

---

## 📁 Project Structure

```
cyber-lockbox-java/
├─ src/
│  └─ Main.java
└─ README.md
```

---

## 📄 License

This project is licensed under the **MIT License**.  
You’re free to use, modify, and share it for educational or personal projects.

---

## 👨‍💻 Author

Developed by **g0utam**  
Originally created in Python, then rebuilt in Java to demonstrate secure coding and cross-language development.  

If you find this project useful, consider starring ⭐ it on GitHub or sharing your feedback!

---
