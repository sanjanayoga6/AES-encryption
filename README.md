# AES-encryption GUI-tool

This project is a **Graphical User Interface (GUI) application** built with **Python** and **Tkinter** to demonstrate **AES (Advanced Encryption Standard)** encryption and decryption using the **PyCryptodome** cryptographic library.

# Features
- Real-time AES encryption and decryption
- GUI built with Tkinter
- Input plaintext and custom AES key
- Supports AES-128, AES-192, and AES-256
- Displays encrypted ciphertext (Base64) and IV
- Allows decryption with correct IV and key
- Proper PKCS7 padding handled automatically
- Easy-to-use interface for learning block ciphers

# What is AES?
AES (Advanced Encryption Standard) is a widely used symmetric block cipher algorithm that encrypts data in 128-bit blocks using secret keys of 128, 192, or 256 bits.

# Used in:
- Wi-Fi security (WPA2, WPA3)
- HTTPS (SSL/TLS)
- VPNs and disk encryption
- Messaging apps (Signal, WhatsApp)

Installation of package: pip install pycryptodome

Clone the repository, run it as python aes_gui.py, the gui window opens up, add your plain text, type the AES key which should be either 16 or 24 or 32 bytes, encrypt the test and you can also decrypt the key. 
