#!/usr/bin/env python3
"""
task4_encryptor.py
AES-256-GCM File Encryptor / Decryptor (Interactive Version with Smart Path Saving)

Now encrypted (.enc) and decrypted files are stored in the same
directory as the original file.
"""

import os
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---- Parameters ----
SALT_SIZE = 16
NONCE_SIZE = 12
KDF_ITERATIONS_DEFAULT = 200_000
KEY_LENGTH = 32  # 256-bit key

# ---- Key derivation ----
def derive_key(password: bytes, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password)

# ---- Encrypt ----
def encrypt_file(in_path: str, password: str, iterations: int = KDF_ITERATIONS_DEFAULT):
    if not os.path.exists(in_path):
        raise FileNotFoundError(f"Input file not found: {in_path}")

    # Generate automatic output file name in same folder
    out_path = in_path + ".enc"

    salt = os.urandom(SALT_SIZE)
    key = derive_key(password.encode("utf-8"), salt, iterations)
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)

    with open(in_path, "rb") as f:
        plaintext = f.read()

    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    with open(out_path, "wb") as f:
        f.write(salt + nonce + ciphertext)

    print(f"\n✅ Encrypted successfully!")
    print(f"📁 Input : {in_path}")
    print(f"📄 Output: {out_path}\n")

# ---- Decrypt ----
def decrypt_file(in_path: str, password: str, iterations: int = KDF_ITERATIONS_DEFAULT):
    if not os.path.exists(in_path):
        raise FileNotFoundError(f"Input file not found: {in_path}")

    with open(in_path, "rb") as f:
        data = f.read()

    if len(data) < (SALT_SIZE + NONCE_SIZE + 16):
        raise ValueError("Encrypted file is too short or corrupted.")

    salt = data[:SALT_SIZE]
    nonce = data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = data[SALT_SIZE + NONCE_SIZE:]

    key = derive_key(password.encode("utf-8"), salt, iterations)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    except Exception:
        raise ValueError("❌ Decryption failed — wrong password or corrupted file.")

    # Remove .enc from name and append _decrypted
    base, ext = os.path.splitext(in_path)
    out_path = base + "_decrypted" + (ext.replace(".enc", "") if ext == ".enc" else "")

    with open(out_path, "wb") as f:
        f.write(plaintext)

    print(f"\n✅ Decrypted successfully!")
    print(f"📁 Input : {in_path}")
    print(f"📄 Output: {out_path}\n")

# ---- Interactive Menu ----
def main():
    print("=" * 60)
    print("🛡️  AES-256-GCM File Encryptor / Decryptor")
    print("=" * 60)
    print("1️⃣  Encrypt a file")
    print("2️⃣  Decrypt a file")
    print("3️⃣  Exit")
    print("-" * 60)

    choice = input("Enter your choice (1-3): ").strip()
    if choice not in ["1", "2"]:
        print("\nExiting. Goodbye!")
        return

    if choice == "1":
        print("\n--- 🔐 File Encryption ---")
        in_path = input("Enter the full path of the file to encrypt: ").strip()
        pwd = getpass.getpass("Enter a strong password: ")
        confirm_pwd = getpass.getpass("Confirm password: ")
        if pwd != confirm_pwd:
            print("❌ Passwords do not match. Try again.")
            return
        try:
            encrypt_file(in_path, pwd)
        except Exception as e:
            print("Error:", e)

    elif choice == "2":
        print("\n--- 🔓 File Decryption ---")
        in_path = input("Enter the full path of the encrypted file (.enc): ").strip()
        pwd = getpass.getpass("Enter password used during encryption: ")
        try:
            decrypt_file(in_path, pwd)
        except Exception as e:
            print("Error:", e)

if __name__ == "__main__":
    main()
