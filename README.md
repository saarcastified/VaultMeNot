# VaultMeNot
A sarcastic yet secure vault to store your secrets – CLI and GUI versions included.

🧠 Fun Fact

VaultMeNot was born from sarcasm, coffee, and the need to store secrets in style.
Your vault, your rules.

🛡️ VaultMeNot

    “Trust me... or don’t. Either way, your secrets are safe.”

VaultMeNot is a minimal yet secure CLI and GUI-based password vault built with Python. Whether you're a terminal ninja or prefer pretty buttons, this tool keeps your credentials encrypted and offline.
🚀 Features

   🔐 AES-encrypted vault file (local, no cloud sync)

   🧠 CLI for terminal lovers

   🖼️ GUI for visual warriors (PyQt5)

   🔍 Search functionality

   🧑‍💻 Add / Edit / Delete entries

   💤 Auto-lock after inactivity (GUI)

   🔒 Keyfile + password support

   🧯 Export vault (with explicit warning)

📦 Requirements

    Python 3.8+

    cryptography

    PyQt5

# How to use
  To use the CLI version of __VaultMeNot__, use:
  ```
  git clone https://github.com/saarcastified/VaultMeNot.git
  ```
Now change pwd to VaultMeNot:
```
cd VaultMeNot
```
To execute the cli version using:
```
python3 vault_cli1.3.py
```
To run the GUI version, in a terminal:
```
python3 vault_gui2.1.py
```
If you're using it for the first time you'll be asked to create a master password:
```
[+] No vault found. Setting up new vault...
Set master password: 
```
After that, Run the application again using:
```
python3 vault_cli1.3.py
```
Enter the master password and use __help__ command to view the commands to use the application:
```
Commands: add, list, view <name>, delete <name>, search <query>, backup, exit
```
You can add entries to save passwords:
```
Name
IP
Username
Password
Notes
```
The __list__ command can be used to view the notes of all entries made. Here you can only view nothing but name of the entry. Based on the name you've kept while saving the entry; we can view the password using:
```
view <name>
```
__Auto Lock__ After 5 minutes of inactivity the application will autolock itself asking you to re-enter the master password.

You can always make a backup of all entries just to be sure using 
```
backup
```
You can delete an entry using:
```
delete <name>
```
🤝 Contributing

Pull Requests welcome!
Have a funny idea or feature request? Open an issue — we appreciate good sarcasm and better code!

Coming Soon!

Windows and Linux Executables.
