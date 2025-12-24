import os
import sys
import requests
import paramiko
import zipfile
import hashlib
from scp import SCPClient
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

class NexusTool:
    def __init__(self):
        self.external_ip = self.get_ip()
        self.banner = f"""
        ================================================
        |          NEXUS-FLOW: SSH & AES-256           |
        |----------------------------------------------|
        |  YOUR EXTERNAL IP: {self.external_ip.ljust(25)} |
        ================================================
        """

    def get_ip(self):
        try:
            return requests.get('https://api.ipify.org', timeout=5).text
        except:
            return "127.0.0.1"

    def encrypt_and_zip(self, path, password, is_folder):
        # 1. Zip the content
        zip_name = "temp_data.zip"
        with zipfile.ZipFile(zip_name, 'w', zipfile.ZIP_DEFLATED) as zipf:
            if is_folder:
                for root, _, files in os.walk(path):
                    for file in files:
                        full_p = os.path.join(root, file)
                        zipf.write(full_p, os.path.relpath(full_p, path))
            else:
                zipf.write(path, os.path.basename(path))
        
        # 2. Encrypt with AES-256
        key = hashlib.sha256(password.encode()).digest()
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        with open(zip_name, 'rb') as f:
            padded_data = pad(f.read(), AES.block_size)
            
        enc_name = f"nexus_bundle_{datetime.now().strftime('%M%S')}.enc"
        with open(enc_name, 'wb') as f:
            f.write(iv + cipher.encrypt(padded_data))
            
        os.remove(zip_name)
        return enc_name

    def decrypt_and_unzip(self, enc_file_path, password):
        try:
            key = hashlib.sha256(password.encode()).digest()
            with open(enc_file_path, 'rb') as f:
                iv = f.read(16)
                encrypted_data = f.read()
            
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
            
            temp_zip = "decrypted_temp.zip"
            with open(temp_zip, 'wb') as f:
                f.write(decrypted_data)
            
            extract_path = enc_file_path.split('.')[0] + "_extracted"
            with zipfile.ZipFile(temp_zip, 'r') as zip_ref:
                zip_ref.extractall(extract_path)
            
            os.remove(temp_zip)
            print(f"\n[+] SUCCESS: Files extracted to folder: {extract_path}")
        except Exception as e:
            print(f"[-] Decryption Failed: Check password or file integrity. Error: {e}")

    def sender_mode(self):
        print("\n[+] Mode: SENDER")
        choice = input("1. Send File\n2. Send Folder\nSelection: ")
        is_folder = True if choice == "2" else False
        path = input(f"Enter path: ").strip('"') # Strip quotes if dragged & dropped
        
        if not os.path.exists(path): return print("[-] Invalid Path")

        print(f"\n[!] YOUR IP: {self.external_ip}")
        target_ip = input("Enter Receiver's IP: ")
        user = input("Enter SSH Username: ")
        ssh_pwd = input("Enter SSH Password: ")
        aes_pwd = input("Set AES Encryption Key: ")

        print("\n" + "="*40 + f"\n  SHARE THIS KEY: {aes_pwd}\n" + "="*40)

        try:
            print("[*] Encrypting...")
            enc_file = self.encrypt_and_zip(path, aes_pwd, is_folder)
            
            print("[*] Connecting via SSH...")
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(target_ip, username=user, password=ssh_pwd)
            
            # Determine remote path (Linux /tmp or Windows User Home)
            remote_path = f"/tmp/{enc_file}" 
            # Simple check if remote might be windows (usually SSH implies Linux server mostly, but just in case)
            
            with SCPClient(client.get_transport()) as scp:
                print(f"[*] Uploading {enc_file}...")
                scp.put(enc_file, remote_path)
            
            os.remove(enc_file)
            print(f"[+] Done. Sent to {target_ip}:{remote_path}")
            client.close()
        except Exception as e:
            print(f"[-] Error: {e}")

    def receiver_mode(self):
        print("\n[+] Mode: RECEIVER")
        print(f"[!] YOUR IP: {self.external_ip} (Give this to sender)")
        print("[*] Waiting for file... (Ensure SSH Server is running)")
        
        input("\nPress Enter AFTER you have received the .enc file to decrypt it...")
        
        enc_file = input("Enter the name/path of received .enc file: ").strip('"')
        if not os.path.exists(enc_file): return print("[-] File not found.")
        
        aes_pwd = input("Enter the AES Key provided by sender: ")
        
        print("[*] Decrypting...")
        self.decrypt_and_unzip(enc_file, aes_pwd)

    def start(self):
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            print(self.banner)
            print("1. SENDER   (Encrypt & Send)")
            print("2. RECEIVER (Decrypt Received File)")
            print("3. EXIT")
            mode = input("\nSelection > ")
            
            if mode == "1": self.sender_mode(); input("\nPress Enter to continue...")
            elif mode == "2": self.receiver_mode(); input("\nPress Enter to continue...")
            elif mode == "3": break

if __name__ == "__main__":
    tool = NexusTool()
    tool.start()
