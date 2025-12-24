# nexus_tool

# Nexus-Flow: Secure SSH Transfer Tool 🛡️

**Nexus-Flow** is a powerful Python tool designed to transfer files and folders securely between two computers using SSH protocols and **AES-256 (Military Grade) Encryption**.

## 🚀 Features
- **Auto IP Detection**: Automatically displays your external IP to share with the peer.
- **AES-256 Encryption**: Encrypts files/folders with a custom password before transmission.
- **Dual Mode**: Works as a **Sender** (Encrypt & Upload) or **Receiver** (Decrypt & Extract).
- **Cross-Platform**: Designed for Terminal/CMD on Windows and Linux.
- **Secure**: Original files are never sent; only the encrypted bundle travels through the network.

## 📦 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/AAB20/nexus_tool
   cd nexus_tool
   pip install -r requirements.txt
   python nexus_tool.py
