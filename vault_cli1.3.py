
import os
import json
import base64
import getpass
import hashlib
import signal
from datetime import datetime, timedelta
from threading import Timer
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes

VAULT_FILE = "vault.enc"
SALT_FILE = "vault.salt"
BACKUP_DIR = "vault_backups"
LOCK_TIMEOUT_SECONDS = 300  # 5 minutes
backend = default_backend()
timer = None

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=backend
    )
    return kdf.derive(password.encode())

def encrypt_data(data: dict, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    json_data = json.dumps(data).encode()
    encrypted = aesgcm.encrypt(nonce, json_data, None)
    return base64.b64encode(nonce + encrypted)

def decrypt_data(enc_data: bytes, key: bytes) -> dict:
    try:
        raw = base64.b64decode(enc_data)
        nonce = raw[:12]
        ciphertext = raw[12:]
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode())
    except Exception:
        raise ValueError("Decryption failed. Wrong password or corrupted vault.")

def save_vault(data: dict, key: bytes):
    with open(VAULT_FILE, "wb") as f:
        f.write(encrypt_data(data, key))

def load_vault(key: bytes) -> dict:
    with open(VAULT_FILE, "rb") as f:
        return decrypt_data(f.read(), key)

def prompt_entry():
    print("Enter new entry details:")
    name = input("Name: ")
    ip = input("IP: ")
    user = input("Username: ")
    password = getpass.getpass("Password: ")
    notes = input("Notes: ")
    return {
        "name": name,
        "ip": ip,
        "username": user,
        "password": password,
        "notes": notes,
        "created_at": str(datetime.now())
    }

def backup_vault():
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    backup_name = f"vault_backup_{timestamp}.enc"
    backup_path = os.path.join(BACKUP_DIR, backup_name)
    with open(VAULT_FILE, "rb") as original, open(backup_path, "wb") as backup:
        backup.write(original.read())
    print(f"[+] Encrypted backup saved as: {backup_path}")

def search_entries(vault_data, query):
    results = []
    for name, entry in vault_data.items():
        if query.lower() in name.lower() or            query.lower() in entry.get("ip", "").lower() or            query.lower() in entry.get("notes", "").lower() or            query.lower() in entry.get("username", "").lower():
            results.append(entry)
    return results

def reset_timer(vault_data, key):
    global timer
    if timer:
        timer.cancel()
    timer = Timer(LOCK_TIMEOUT_SECONDS, auto_lock, [vault_data, key])
    timer.start()

def auto_lock(vault_data, key):
    save_vault(vault_data, key)
    print("\n[!] Vault auto-locked due to inactivity. Even your keyboard fell asleep. 💤🔒")
    os._exit(0)

def vault_shell(vault_data, key):
    print("[i] Auto-lock is set to 5 minutes of inactivity.")
    reset_timer(vault_data, key)
    while True:
        try:
            cmd = input("vault> ").strip().lower()
            reset_timer(vault_data, key)
            if cmd == "help":
                print("Commands: add, list, view <name>, delete <name>, search <query>, backup, exit")
            elif cmd == "add":
                entry = prompt_entry()
                vault_data[entry["name"]] = entry
            elif cmd == "list":
                if vault_data:
                    for name in vault_data:
                        print(f"- {name}")
                else:
                    print("Vault is empty.")
            elif cmd.startswith("view "):
                name = cmd[5:].strip()
                if name in vault_data:
                    for k, v in vault_data[name].items():
                        print(f"{k.capitalize()}: {v}")
                else:
                    print("Entry not found.")
            elif cmd.startswith("delete "):
                name = cmd[7:].strip()
                if name in vault_data:
                    del vault_data[name]
                    print(f"Deleted entry: {name}")
                else:
                    print("Entry not found.")
            elif cmd.startswith("search "):
                query = cmd[7:].strip()
                matches = search_entries(vault_data, query)
                if matches:
                    for entry in matches:
                        print("---------------")
                        for k, v in entry.items():
                            print(f"{k.capitalize()}: {v}")
                else:
                    print("No matching entries found.")
            elif cmd == "backup":
                backup_vault()
            elif cmd == "exit":
                save_vault(vault_data, key)
                print("[+] Vault saved and encrypted. Goodbye!")
                break
            else:
                print("Unknown command. Type 'help' for options.")
        except KeyboardInterrupt:
            print("\n[!] Ctrl+C detected. Vault saved and locked.")
            save_vault(vault_data, key)
            break

def main():
    if not os.path.exists(VAULT_FILE):
        print("[+] No vault found. Setting up new vault...")
        password = getpass.getpass("Set master password: ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("[!] Passwords do not match.")
            return
        salt = os.urandom(16)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
        key = derive_key(password, salt)
        save_vault({}, key)
        print("[+] Vault created successfully.")
    else:
        password = getpass.getpass("Enter master password to unlock vault: ")
        if not os.path.exists(SALT_FILE):
            print("[!] Salt file missing. Cannot decrypt vault.")
            return
        with open(SALT_FILE, "rb") as f:
            salt = f.read()
        try:
            key = derive_key(password, salt)
            vault_data = load_vault(key)
            print("[+] Vault unlocked.")
            vault_shell(vault_data, key)
        except ValueError:
            print("[!] Incorrect password or corrupted vault.")

if __name__ == "__main__":
    main()
