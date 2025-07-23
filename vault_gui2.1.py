import sys
import json
import base64
import os
import getpass
from PyQt5.QtWidgets import (
    QApplication, QWidget, QMainWindow, QLabel, QLineEdit, QPushButton, QVBoxLayout,
    QHBoxLayout, QListWidget, QTextEdit, QMessageBox, QInputDialog, QFormLayout,
    QDialog, QDialogButtonBox, QFileDialog
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QPalette, QColor
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VAULT_FILE = "vault.enc"
SALT_FILE = "vault.salt"
AUTO_LOCK_TIMEOUT = 5 * 60 * 1000  # 5 minutes


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
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
        raise ValueError("Decryption failed.")


class AddEntryDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Add New Entry")
        self.layout = QFormLayout()

        self.name_input = QLineEdit()
        self.ip_input = QLineEdit()
        self.username_input = QLineEdit()
        self.password_input = QLineEdit()
        self.notes_input = QTextEdit()

        self.layout.addRow("Name:", self.name_input)
        self.layout.addRow("IP Address:", self.ip_input)
        self.layout.addRow("Username:", self.username_input)
        self.layout.addRow("Password:", self.password_input)
        self.layout.addRow("Notes:", self.notes_input)

        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)

        self.layout.addWidget(self.buttons)
        self.setLayout(self.layout)

    def get_data(self):
        return {
            "name": self.name_input.text(),
            "ip": self.ip_input.text(),
            "username": self.username_input.text(),
            "password": self.password_input.text(),
            "notes": self.notes_input.toPlainText(),
            "created_at": str(getpass.getuser())
        }


class VaultWindow(QMainWindow):
    def __init__(self, vault_data, key):
        super().__init__()
        self.setWindowTitle("Secure Vault")
        self.vault_data = vault_data
        self.key = key
        self.dark_mode = False

        self.timer = QTimer()
        self.timer.timeout.connect(self.auto_lock)
        self.reset_timer()

        self.init_ui()

    def reset_timer(self):
        self.timer.start(AUTO_LOCK_TIMEOUT)

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search...")
        self.search_input.textChanged.connect(self.refresh_entries)

        self.entry_list = QListWidget()
        self.entry_list.itemClicked.connect(self.display_entry)

        self.detail_view = QTextEdit()
        self.detail_view.setReadOnly(True)

        add_btn = QPushButton("Add")
        add_btn.clicked.connect(self.add_entry)

        edit_btn = QPushButton("Edit")
        edit_btn.clicked.connect(self.edit_entry)

        delete_btn = QPushButton("Delete")
        delete_btn.clicked.connect(self.delete_entry)

        backup_btn = QPushButton("Backup")
        backup_btn.clicked.connect(self.backup_vault)

        export_btn = QPushButton("Export Decrypted")
        export_btn.clicked.connect(self.export_decrypted)

        lock_btn = QPushButton("Lock Now")
        lock_btn.clicked.connect(self.save_and_lock)

        about_btn = QPushButton("About")
        about_btn.clicked.connect(self.show_about)

        darkmode_btn = QPushButton("Toggle Dark Mode")
        darkmode_btn.clicked.connect(self.toggle_dark_mode)

        left_layout = QVBoxLayout()
        left_layout.addWidget(QLabel("Search Entries"))
        left_layout.addWidget(self.search_input)
        left_layout.addWidget(self.entry_list)
        left_layout.addWidget(add_btn)
        left_layout.addWidget(edit_btn)
        left_layout.addWidget(delete_btn)
        left_layout.addWidget(backup_btn)
        left_layout.addWidget(export_btn)
        left_layout.addWidget(lock_btn)
        left_layout.addWidget(darkmode_btn)
        left_layout.addWidget(about_btn)

        right_layout = QVBoxLayout()
        right_layout.addWidget(QLabel("Details"))
        right_layout.addWidget(self.detail_view)

        main_layout = QHBoxLayout()
        main_layout.addLayout(left_layout, 3)
        main_layout.addLayout(right_layout, 5)

        central_widget.setLayout(main_layout)
        self.refresh_entries()

    def toggle_dark_mode(self):
        self.reset_timer()
        app = QApplication.instance()
        palette = QPalette()
        if not self.dark_mode:
            palette.setColor(QPalette.Window, QColor(53, 53, 53))
            palette.setColor(QPalette.WindowText, Qt.white)
            palette.setColor(QPalette.Base, QColor(25, 25, 25))
            palette.setColor(QPalette.Text, Qt.white)
            palette.setColor(QPalette.Button, QColor(53, 53, 53))
            palette.setColor(QPalette.ButtonText, Qt.white)
            self.dark_mode = True
        else:
            palette = app.style().standardPalette()
            self.dark_mode = False
        app.setPalette(palette)

    def auto_lock(self):
        QMessageBox.information(self, "Auto Lock", "Vault locked due to inactivity. Even hackers nap. 😴🔐")
        self.save_and_lock()

    def refresh_entries(self):
        self.reset_timer()
        query = self.search_input.text().lower()
        self.entry_list.clear()
        for name in self.vault_data:
            if query in name.lower():
                self.entry_list.addItem(name)

    def display_entry(self, item):
        self.reset_timer()
        entry = self.vault_data[item.text()]
        self.detail_view.setText(
            f"Name: {entry['name']}\nIP: {entry['ip']}\nUsername: {entry['username']}\n"
            f"Password: {entry['password']}\nNotes: {entry['notes']}\nCreated At: {entry['created_at']}"
        )

    def save_vault(self):
        with open(VAULT_FILE, "wb") as f:
            f.write(encrypt_data(self.vault_data, self.key))

    def add_entry(self):
        self.reset_timer()
        dialog = AddEntryDialog()
        if dialog.exec_() == QDialog.Accepted:
            data = dialog.get_data()
            self.vault_data[data['name']] = data
            self.refresh_entries()
            self.save_vault()

    def edit_entry(self):
        self.reset_timer()
        selected = self.entry_list.currentItem()
        if selected:
            name = selected.text()
            entry = self.vault_data[name]
            ip, _ = QInputDialog.getText(self, "Edit IP", "Edit IP:", text=entry["ip"])
            user, _ = QInputDialog.getText(self, "Edit Username", "Edit username:", text=entry["username"])
            pwd, _ = QInputDialog.getText(self, "Edit Password", "Edit password:", text=entry["password"])
            notes, _ = QInputDialog.getMultiLineText(self, "Edit Notes", "Edit notes:", text=entry["notes"])
            entry.update({"ip": ip, "username": user, "password": pwd, "notes": notes})
            self.refresh_entries()
            self.display_entry(selected)
            self.save_vault()

    def delete_entry(self):
        self.reset_timer()
        selected = self.entry_list.currentItem()
        if selected:
            name = selected.text()
            confirm = QMessageBox.question(self, "Confirm Delete", f"Delete '{name}'?",
                                           QMessageBox.Yes | QMessageBox.No)
            if confirm == QMessageBox.Yes:
                del self.vault_data[name]
                self.refresh_entries()
                self.detail_view.clear()
                self.save_vault()

    def backup_vault(self):
        self.reset_timer()
        if not os.path.exists("vault_backups"):
            os.makedirs("vault_backups")
        backup_name = "vault_backups/vault_backup_gui.enc"
        with open(backup_name, "wb") as f:
            f.write(encrypt_data(self.vault_data, self.key))
        QMessageBox.information(self, "Backup", f"Backup saved to: {backup_name}")

    def export_decrypted(self):
        self.reset_timer()
        confirm = QMessageBox.warning(
            self, "Export Decrypted Vault",
            "Exporting in decrypted form. Proceed only if you understand the risk!",
            QMessageBox.Yes | QMessageBox.No
        )
        if confirm == QMessageBox.Yes:
            file_path, _ = QFileDialog.getSaveFileName(self, "Export JSON", "vault_decrypted.json", "JSON Files (*.json)")
            if file_path:
                with open(file_path, "w") as f:
                    json.dump(self.vault_data, f, indent=2)
                QMessageBox.information(self, "Export", f"Decrypted vault exported to {file_path}")

    def show_about(self):
        QMessageBox.information(self, "About", (
            "🔐 Secure Vault by Rocky\n\n"
            "Built for paranoid professionals who prefer their passwords local.\n"
            "Encrypted using AES-GCM. No clouds were harmed.\n"
            "💬 'Even if someone steals your drive, all they get is encrypted regret.'\n\n"
            "Made with Kali, sarcasm, and strong coffee."
        ))

    def save_and_lock(self):
        self.save_vault()
        self.close()
        self.lock_screen = UnlockWindow()
        self.lock_screen.show()


class UnlockWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Unlock Vault")
        self.resize(300, 100)
        layout = QVBoxLayout()

        self.label = QLabel("Enter master password:")
        self.pass_input = QLineEdit()
        self.pass_input.setEchoMode(QLineEdit.Password)
        self.pass_input.returnPressed.connect(self.unlock)  # <== Enter Key Support
        self.unlock_btn = QPushButton("Unlock")
        self.unlock_btn.clicked.connect(self.unlock)

        layout.addWidget(self.label)
        layout.addWidget(self.pass_input)
        layout.addWidget(self.unlock_btn)
        self.setLayout(layout)

    def unlock(self):
        password = self.pass_input.text()
        if not os.path.exists(SALT_FILE):
            QMessageBox.critical(self, "Error", "Salt file missing.")
            return
        with open(SALT_FILE, "rb") as f:
            salt = f.read()
        try:
            key = derive_key(password, salt)
            if os.path.exists(VAULT_FILE):
                with open(VAULT_FILE, "rb") as f:
                    vault_data = decrypt_data(f.read(), key)
            else:
                vault_data = {}
                with open(VAULT_FILE, "wb") as f:
                    f.write(encrypt_data(vault_data, key))
                with open(SALT_FILE, "wb") as f:
                    f.write(salt)
            self.main_window = VaultWindow(vault_data, key)
            self.main_window.show()
            self.close()
        except Exception:
            QMessageBox.critical(self, "Error", "Failed to unlock vault.")


def main():
    app = QApplication(sys.argv)
    window = UnlockWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
