import tkinter as tk
from tkinter import messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

# AES Functions
def encrypt_aes(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv, ct

def decrypt_aes(iv, ciphertext, key):
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ciphertext)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')

# GUI Functions
def encrypt_text():
    plaintext = entry_plain.get("1.0", tk.END).strip()
    key_input = entry_key.get().strip()
    key = key_input.encode('utf-8')

    if len(key) not in [16, 24, 32]:
        messagebox.showerror("Invalid Key", "Key must be 16, 24, or 32 bytes long!")
        return

    try:
        iv, ciphertext = encrypt_aes(plaintext, key)
        entry_cipher.delete("1.0", tk.END)
        entry_cipher.insert(tk.END, ciphertext)
        entry_iv.delete(0, tk.END)
        entry_iv.insert(0, iv)
    except Exception as e:
        messagebox.showerror("Error", str(e))

def decrypt_text():
    ciphertext = entry_cipher.get("1.0", tk.END).strip()
    key_input = entry_key.get().strip()
    iv = entry_iv.get().strip()
    key = key_input.encode('utf-8')

    if len(key) not in [16, 24, 32]:
        messagebox.showerror("Invalid Key", "Key must be 16, 24, or 32 bytes long!")
        return

    try:
        decrypted = decrypt_aes(iv, ciphertext, key)
        entry_decrypt.delete("1.0", tk.END)
        entry_decrypt.insert(tk.END, decrypted)
    except Exception as e:
        messagebox.showerror("Error", str(e))

# GUI Setup
root = tk.Tk()
root.title("AES Encryption Tool")
root.geometry("620x570")
root.resizable(False, False)
root.configure(bg="#1e1e1e")  # Dark background

label_opts = {"bg": "#1e1e1e", "fg": "white", "font": ("Segoe UI", 10, "bold")}
entry_bg = "#2e2e2e"
entry_fg = "#ffffff"

# Labels and Inputs
tk.Label(root, text="Enter Plaintext:", **label_opts).pack(pady=(10, 0))
entry_plain = tk.Text(root, height=4, width=70, bg=entry_bg, fg=entry_fg, insertbackground="white")
entry_plain.pack()

tk.Label(root, text="Enter AES Key (16/24/32 bytes):", **label_opts).pack()
entry_key = tk.Entry(root, width=40, bg=entry_bg, fg=entry_fg, insertbackground="white")
entry_key.pack()

# Encrypt Button
tk.Button(root, text="Encrypt", command=encrypt_text, bg="#4CAF50", fg="white", font=("Segoe UI", 10, "bold"), width=20).pack(pady=10)

tk.Label(root, text="Generated IV (Base64):", **label_opts).pack()
entry_iv = tk.Entry(root, width=70, bg=entry_bg, fg=entry_fg, insertbackground="white")
entry_iv.pack()

tk.Label(root, text="Ciphertext (Base64):", **label_opts).pack()
entry_cipher = tk.Text(root, height=4, width=70, bg=entry_bg, fg=entry_fg, insertbackground="white")
entry_cipher.pack()

# Decrypt Button
tk.Button(root, text="Decrypt", command=decrypt_text, bg="#2196F3", fg="white", font=("Segoe UI", 10, "bold"), width=20).pack(pady=10)

tk.Label(root, text="Decrypted Plaintext:", **label_opts).pack()
entry_decrypt = tk.Text(root, height=4, width=70, bg=entry_bg, fg=entry_fg, insertbackground="white")
entry_decrypt.pack()

root.mainloop()
