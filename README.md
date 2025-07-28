# 🔐 PassMan — Modern, Secure, Offline-First Password Manager

> A zero-trust, self-hosted password manager built with Flask, HTMX, and cutting-edge cryptography.

---

## 🚀 Why PassMan?

Most password managers either trust their cloud backend — or compromise on usability.  
**PassMan** is built to be fully offline (or self-hosted), with **military-grade encryption**, **user-friendly design**, and **modern security practices**.

It's built from scratch. No browser plugins. No vendor lock-in. **Your data. Your keys. Your rules.**

---

## 🧠 Features

- 🔑 **Secure Vault Storage** using AES-GCM encryption with Argon2id key derivation.
- 🧪 **Password Breach Checker** powered by [HaveIBeenPwned](https://haveibeenpwned.com/API).
- 🧬 **Two-Factor Authentication** via TOTP (Google Authenticator-compatible).
- 📁 **Backup File Login**: Restore access using an encrypted local file.
- 🎲 **Random Password Generator**: Generate high-entropy credentials with a click.
- 🧼 Minimal, elegant **HTMX-powered UI**.
- 🛡️ CSRF protection, rate limiting, and user session isolation.
- 🕵️ Fully server-side. **No password ever leaves your machine in plaintext.**

---

## 🧱 Tech Stack

| Layer       | Tech                  |
|-------------|------------------------|
| Backend     | Python, Flask, SQLite  |
| Frontend    | Bootstrap, HTMX        |
| Crypto      | `cryptography`, AES-GCM, Argon2id |
| 2FA         | `pyotp`, QR via `qrcode` + `Pillow` |
| Breach Check| HIBP API (`k-anonymity` via SHA1 prefix) |
| Login Rate  | `flask-limiter`        |
| Session     | `flask-login`          |

---

## 📸 Screenshots

| Vault | 2FA Setup | Breach Dashboard |
|-------|-----------|------------------|
| ![vault](https://raw.githubusercontent.com/TudorOO/PassMan/main/docs/vault.png) | ![2fa](https://raw.githubusercontent.com/TudorOO/PassMan/main/docs/2fa.png) | ![breach](https://raw.githubusercontent.com/TudorOO/PassMan/main/docs/breach.png) |

> *(Add screenshots under `/docs/` if you want these to show up.)*

---

## 🧪 Security Design

PassMan uses a **zero-trust approach**:

- Vault passwords are encrypted **individually** with a derived key from the master password.
- Nothing is stored in plaintext. Even in-memory operations avoid leaks.
- Passwords are hashed with Argon2id (memory-hard, slow, resistant to GPU brute-force).
- Authentication supports 2FA via QR + TOTP.
- Breach checks are performed without leaking full passwords using SHA-1 `k-anonymity` ranges.

📖 See `crypto.py` and `backup.py` for full implementation details.

---

## 🛠 How to Run Locally

```bash
git clone https://github.com/TudorOO/PassMan.git
cd PassMan
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run the Flask app
flask --app webapp run

    📌 Requires Python 3.10+ and Linux/macOS for full functionality.

🔐 Disclaimer

DO NOT USE THIS FOR STORING REAL CREDENTIALS.
This project is for educational and demonstration purposes only.

While strong cryptography is used, no audit has been performed, and it's meant to showcase secure coding practices — not replace commercial password managers.
🧑‍💻 Author

Tudor O.
High school student passionate about cybersecurity and secure systems.
Building open-source projects to learn, grow, and hopefully impress some recruiters :)

🌐 GitHub
⭐️ Star this project if you like it!