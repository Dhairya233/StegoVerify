# StegoVerify
# 🔑 Project The KEY: Digital Forensics Suite

## 🚀 Overview

**Project The KEY** (internally known as **StegoVerify**) is a Python-based graphical user interface (GUI) application designed to demonstrate and utilize fundamental concepts in **Cryptography, Steganography, and Digital Forensics**. It provides a set of tools that allow users to hide/extract secret messages in images, encrypt/decrypt text using classic ciphers, and verify file integrity using cryptographic hashing.

Built with `tkinter` for the GUI and utilizing the `Pillow` library for image manipulation, this suite is a powerful educational and utility tool for understanding data security and covert communications.

## ✨ Features

The application is organized into three main modules:

### 1. Text Ciphers
* **Vigenère Cipher:** Encrypt and decrypt textual messages using a polyalphabetic substitution cipher, demonstrating classical cryptography.
* **Morse Code:** Encode plain text into Morse sequences and decode Morse back into text.

### 2. Multimedia Steganography
* **LSB (Least Significant Bit) Image Steganography:** Hide a secret text message within a PNG image file by altering the least significant bit of its color channels, and extract the hidden message back.
* **Image Preview:** Built-in thumbnail preview for selected images.

### 3. Digital Forensics
* **SHA-256 Hashing:** Calculate the unique SHA-256 "digital fingerprint" for any file (image, audio, etc.) to verify its integrity.
* **Hash Comparison:** Compare two SHA-256 hashes to instantly determine if two files are identical or if one has been tampered with.

## 🛠️ Installation

### Prerequisites

To run this application, you must have **Python 3.x** installed. The project relies on the following external libraries:

* `Pillow` (PIL) for image handling.

### Setup Steps

1.  **Clone the Repository:**
    ```bash
    git clone [YOUR_REPOSITORY_URL]
    cd StegoVerify
    ```

2.  **Install Required Libraries:**
    Install the necessary dependencies using pip:
    ```bash
    pip install Pillow
    ```

3.  **Run the Application:**
    Execute the main script from your terminal:
    ```bash
    python [your_script_name].py 
    # e.g., python StegoVerify.py
    ```

## 💻 Usage

The application features a dark, "Matrix Aesthetic" interface with three dedicated tabs.

### Tab 1: Text Ciphers
1.  Enter your **Plaintext** or **Ciphertext** and the **Key** for Vigenère operations.
2.  Use the dedicated **Morse Code** section to quickly translate messages.

### Tab 2: Multimedia Stego
1.  Click **"Select Image File"** to choose a base image (PNG recommended for LSB).
2.  Enter the **Message to Hide** and click **"ENCRYPT IMAGE"** to save the stego-image.
3.  Click **"DECRYPT IMAGE"** to extract the hidden message from a selected image.

### Tab 3: Digital Forensics
1.  Click **"Select File"** and then **"CALCULATE FINGERPRINT"** to generate the SHA-256 hash.
2.  Paste two separate hash values into the **Compare Two Hashes** section and click **"COMPARE"** to check for integrity.


## 📄 License

This project is released under the **[License Type, e.g., MIT]** license.

---
**Developed By: Dhairya Shah**
