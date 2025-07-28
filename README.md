PassMan — Your Own Secure Password Manager

A simple, secure, and self-hosted password manager built for privacy-first users.

PassMan is a lightweight password manager that focuses on client-side encryption, zero-trust principles, and usability. Designed to be hosted privately, it never sends unencrypted secrets to the server, and it makes no compromises when it comes to protecting your data.

🚀 Features

Client-side encryption (AES-GCM + Argon2id): Your passwords never leave the browser unencrypted.

Backup file login: Authenticate using an encrypted file you own.

Master password caching: Optional, minimal exposure in RAM.

Two-Factor Authentication (TOTP, QR code-based).

HIBP breach checker: See if any of your passwords have been exposed, using the k-anonymity model.

Password generator: One-click random key generation.

HTMX-enhanced UI: No heavy frontend frameworks.

Rate limiting, CSRF protection, and session control out of the box.

🔧 How It Works

Each password is encrypted using a randomly generated key, which is itself encrypted with a key derived from your master password.

The master password is never stored anywhere, not even in memory unless strictly needed.

2FA secrets are generated and stored encrypted, and verified using TOTP when enabled.

The HIBP API is used to check for password exposure without ever sending your full password.

🧰 Stack

Backend: Flask (Python)

Frontend: Bootstrap + HTMX + vanilla JS

Crypto: AES-GCM (from cryptography), Argon2id (via argon2-cffi)

Database: SQLite

Others: Flask-Login, Flask-Limiter, PyOTP, qrcode, Pillow

💡 Why I Built This

I wanted a password manager that didn't just claim to be secure, but actually gave me control. Something I could host, audit, and understand. I didn't want my passwords sitting in someone else's cloud, and I wanted to practice modern security principles. So I built PassMan.

This is a personal learning project, but one that puts security and clean design first. Everything is built by hand: the login flow, the encryption logic, the breach checks, and the 2FA system.

🎓 Who Is This For?

Security enthusiasts and students looking for inspiration.

Recruiters or universities evaluating secure coding skills.

Anyone who wants to see a fully working, end-to-end secure app built from scratch.

⚖️ Important Note

DO NOT USE FOR STORING REAL PASSWORDS YET.

This project is not audited and was built for educational purposes. If you'd like to reuse or adapt it, make sure to do your own security review.

📚 Setup

git clone https://github.com/TudorOO/PassMan.git
cd PassMan
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
flask --app webapp run

Runs on: Python 3.10+

👁️ Screenshot Preview

Add these under /docs/:

Vault screen

QR code modal

Breach check dashboard

🚀 Future Ideas

Geo-fencing login support

Secure note storage

Password change workflow with app auto-updates

U2F / WebAuthn support

Mobile-first responsive redesign

👤 Author

Tudor O.Student passionate about security and systems programming. Always experimenting, always building.

GitHub: @TudorOO

⭐ If this helped you, give it a star!

