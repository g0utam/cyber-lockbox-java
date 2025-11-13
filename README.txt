# 🔐 Cyber Lockbox Pro - Java (Swing)

A modern AES-256 GCM file encryption/decryption tool written in Java Swing. 
Converted from the original Python version for portfolio showcasing.

## ⚙️ Features
- AES-256 GCM encryption and decryption
- PBKDF2WithHmacSHA256 key derivation (480,000 iterations)
- Cross-compatible with the original Python version
- Simple, dark-themed Swing GUI

## 🧱 Project Structure
```
cyber-lockbox-java/
├─ src/
│  └─ Main.java
```

## ▶️ How to Run
```bash
javac -d out src/Main.java
java -cp out Main
```

## 🧠 Notes
- Requires **Java 11+** for PBKDF2WithHmacSHA256.
- Compatible with files from the Python Cyber Lockbox.

## 🧑‍💻 Author
Developed by g0utam | Ported to Java by ChatGPT
