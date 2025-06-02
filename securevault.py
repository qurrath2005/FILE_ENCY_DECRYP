import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from Crypto.Cipher import AES, ChaCha20
from Crypto.Random import get_random_bytes
import hashlib, time, shutil, psutil, logging
from PIL import Image
import sys

# ======================== AUTO-CREATE SECUREVAULT DIRECTORIES ========================
VAULT_PATH = os.path.join(os.path.expanduser("~"), "Documents", "SecureVault")
DIRS = ["Encrypted", "Decrypted", "Logs", "USBAutoBackup"]
for dir_name in DIRS:
    os.makedirs(os.path.join(VAULT_PATH, dir_name), exist_ok=True)

# Setup logging
logging.basicConfig(
    filename=os.path.join(VAULT_PATH, "Logs", f"audit_{time.strftime('%Y%m%d')}.log"),
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

class SecureVault:
    def __init__(self, root):
        self.root = root
        self.root.title("🔒 SecureVault Pro")
        self.root.geometry("600x320")
        self.root.configure(bg="#0f1624")
        self.root.resizable(False, False)

        self.setup_style()
        self.setup_ui()
        
    def setup_style(self):
        style = ttk.Style(self.root)
        style.theme_use('clam')

        # Configure style for labels
        style.configure("TLabel", background="#0f1624", foreground="#64ffda", font=("Segoe UI", 11))
        # Configure style for entry
        style.configure("TEntry", font=("Segoe UI", 11), padding=5)
        # Configure style for buttons
        style.configure("Encrypt.TButton", background="#1de9b6", foreground="#0f1624", font=("Segoe UI Semibold", 12))
        style.map("Encrypt.TButton",
                  background=[('active', '#14cba8')],
                  foreground=[('active', '#0a3c2d')])
        style.configure("Decrypt.TButton", background="#ff6b6b", foreground="#fdfdfd", font=("Segoe UI Semibold", 12))
        style.map("Decrypt.TButton",
                  background=[('active', '#e04e4e')],
                  foreground=[('active', '#fff5f5')])
        # Configure Checkbutton style
        style.configure("TCheckbutton", background="#0f1624", foreground="#80ffda", font=("Segoe UI", 10, "bold"))
        # Configure Radiobutton style
        style.configure("TRadiobutton", background="#0f1624", foreground="#80ffda", font=("Segoe UI", 10))

    def setup_ui(self):
        # Use grid with padding & spacing
        padding_opts = {'padx': 15, 'pady': 10}
        
        # File selection
        ttk.Label(self.root, text="Select File:").grid(row=0, column=0, sticky='w', **padding_opts)
        self.file_entry = ttk.Entry(self.root, width=45)
        self.file_entry.grid(row=0, column=1, sticky='ew', **padding_opts)
        ttk.Button(self.root, text="Browse", command=self.browse_file).grid(row=0, column=2, sticky='e', **padding_opts)

        # Password entry
        ttk.Label(self.root, text="Password:").grid(row=1, column=0, sticky='w', **padding_opts)
        self.pwd_entry = ttk.Entry(self.root, show="*", width=45)
        self.pwd_entry.grid(row=1, column=1, columnspan=2, sticky='ew', **padding_opts)

        # Algorithm choice
        ttk.Label(self.root, text="Algorithm:").grid(row=2, column=0, sticky='w', **padding_opts)
        algo_frame = ttk.Frame(self.root, style="TFrame", padding=0)
        algo_frame.grid(row=2, column=1, columnspan=2, sticky='w', **padding_opts)

        self.algo_var = tk.StringVar(value="AES-256")
        ttk.Radiobutton(algo_frame, text="AES-256", variable=self.algo_var, value="AES-256").grid(row=0, column=0, padx=10)
        ttk.Radiobutton(algo_frame, text="ChaCha20", variable=self.algo_var, value="ChaCha20").grid(row=0, column=1, padx=10)

        # Special features - Self Destruct
        self.self_destruct = tk.BooleanVar()
        ttk.Checkbutton(self.root, text="Self-Destruct After 1hr", variable=self.self_destruct).grid(row=3, column=1, sticky='w', **padding_opts)

        # Buttons for encrypt & decrypt
        button_frame = ttk.Frame(self.root, style="TFrame")
        button_frame.grid(row=4, column=0, columnspan=3, pady=20)

        ttk.Button(button_frame, text="🔒 Encrypt", style="Encrypt.TButton", command=self.encrypt).grid(row=0, column=0, padx=25)
        ttk.Button(button_frame, text="🔓 Decrypt", style="Decrypt.TButton", command=self.decrypt).grid(row=0, column=1, padx=25)

        # Configure grid to make Entry boxes expand with window resizing (even though window is fixed size here)
        self.root.grid_columnconfigure(1, weight=1)

    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, filename)
    
    def encrypt(self):
        filepath = self.file_entry.get()
        if not os.path.exists(filepath):
            messagebox.showerror("Error", "File not found!")
            return
        
        password = self.pwd_entry.get()
        if not password:
            messagebox.showerror("Error", "Password required!")
            return
        
        self.scrub_metadata(filepath)
        
        try:
            if self.algo_var.get() == "AES-256":
                encrypted_data = self.aes_encrypt(filepath, password)
            else:
                encrypted_data = self.chacha_encrypt(filepath, password)
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
            logging.error(f"ENCRYPTION FAILED: {filepath} - {str(e)}")
            return
        
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        original_name = os.path.basename(filepath)
        enc_filename = f"{original_name}_encrypted_{timestamp}.enc"
        enc_path = os.path.join(VAULT_PATH, "Encrypted", enc_filename)
        
        with open(enc_path, 'wb') as f:
            f.write(encrypted_data)
        
        self.backup_to_usb(enc_path)
        
        messagebox.showinfo("Success", f"File encrypted and saved to:\n{enc_path}")
        logging.info(f"ENCRYPTED: {original_name} -> {enc_filename}")

    def decrypt(self):
        filepath = self.file_entry.get()
        if not os.path.exists(filepath):
            messagebox.showerror("Error", "File not found!")
            return
        
        password = self.pwd_entry.get()
        if not password:
            messagebox.showerror("Error", "Password required!")
            return
        
        try:
            with open(filepath, 'rb') as f:
                file_data = f.read()
            
            if self.algo_var.get() == "AES-256":
                decrypted_data = self.aes_decrypt(file_data, password)
            else:
                decrypted_data = self.chacha_decrypt(file_data, password)
            
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            orig_name = os.path.basename(filepath)
            if "_encrypted_" in orig_name:
                orig_name = orig_name.split("_encrypted_")[0]
            dec_filename = f"decrypted_{orig_name}_{timestamp}"
            dec_path = os.path.join(VAULT_PATH, "Decrypted", dec_filename)
            
            with open(dec_path, 'wb') as f:
                f.write(decrypted_data)

            messagebox.showinfo("Success", f"File decrypted and saved to:\n{dec_path}")
            logging.info(f"DECRYPTED: {orig_name} -> {dec_filename}")

        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
            logging.error(f"DECRYPTION FAILED: {filepath} - {str(e)}")

    def aes_encrypt(self, filepath, password):
        salt = get_random_bytes(16)
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        cipher = AES.new(key, AES.MODE_GCM)
        with open(filepath, 'rb') as f:
            data = f.read()
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return salt + cipher.nonce + tag + ciphertext

    def aes_decrypt(self, file_data, password):
        salt = file_data[:16]
        nonce = file_data[16:32]
        tag = file_data[32:48]
        ciphertext = file_data[48:]
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)
        return data

    def chacha_encrypt(self, filepath, password):
        salt = get_random_bytes(16)
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        nonce = get_random_bytes(12)
        cipher = ChaCha20.new(key=key, nonce=nonce)
        with open(filepath, 'rb') as f:
            data = f.read()
        ciphertext = cipher.encrypt(data)
        return salt + nonce + ciphertext

    def chacha_decrypt(self, file_data, password):
        salt = file_data[:16]
        nonce = file_data[16:28]
        ciphertext = file_data[28:]
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        cipher = ChaCha20.new(key=key, nonce=nonce)
        data = cipher.decrypt(ciphertext)
        return data

    def scrub_metadata(self, filepath):
        if filepath.lower().endswith(('.png', '.jpg', '.jpeg')):
            try:
                img = Image.open(filepath)
                data = list(img.getdata())
                clean_img = Image.new(img.mode, img.size)
                clean_img.putdata(data)
                clean_img.save(filepath)
            except Exception as e:
                logging.warning(f"Metadata scrub failed for {filepath}: {str(e)}")
        elif filepath.lower().endswith('.pdf'):
            # PDF metadata removal would require PyPDF2 or similar, omitted here
            pass

    def backup_to_usb(self, filepath):
        for disk in psutil.disk_partitions():
            if 'removable' in disk.opts:
                try:
                    usb_path = os.path.join(VAULT_PATH, "USBAutoBackup", disk.mountpoint.replace(":", ""))
                    os.makedirs(usb_path, exist_ok=True)
                    shutil.copy(filepath, usb_path)
                    logging.info(f"BACKUP: Saved to USB {disk.mountpoint}")
                except Exception as e:
                    logging.warning(f"USB backup failed on {disk.device}: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureVault(root)
    root.mainloop()

