## 🚀 Docker Setup

1. **Clone the repository**

```bash
git clone https://github.com/TudorOO/PassMan.git
cd PassMan

    Build the Docker image

docker build -t passman .

    Create a .env file

Create a .env file in the root directory with your secrets (example below):

SECRET_KEY=your-secret-key
ENCRYPTION_KEY=...
DATABASE_URL=sqlite:///db.sqlite3

    Run the container

docker run --env-file .env -p 8000:8000 passman

    Access the app

Open http://localhost:8000 in your browser.


---

Let me know if you want me to integrate this cleanly into your full README, with formatting and tweaks.

You said:
integrate it baby
ChatGPT said:

Sure thing! Here's a clean and polished version of your README with the full Docker setup section integrated. It's structured, polished, and avoids sounding AI-written — aiming for that “🔥 this dev knows what they’re doing” vibe:

# 🔐 PassMan — Your Secure, Self-Hosted Password Vault

PassMan is a privacy-first, open-source password manager built with Flask, SQLite, and strong cryptography. It offers both client-side and server-side encryption, TOTP-based 2FA, breach detection via HaveIBeenPwned, and a responsive Bootstrap interface.

No tracking, no data mining — just secure, local-first password storage.

---

## ✨ Features

- 🧠 Master password with AES-GCM + Argon2id key derivation
- 🔐 Client-side encryption with WebCrypto API
- 🌐 TOTP 2FA support with QR code provisioning
- 📦 Encrypted backup files
- 🔎 Breach check integration with HaveIBeenPwned (k-anonymity API)
- 🔄 Password reset with master key recovery
- 📱 Mobile-friendly UI with Bootstrap
- 💨 HTMX-powered UI for smooth, dynamic interactions
- 💥 Secure by default (CSRF, sessions, content security headers)

---

## 🚀 Setup

### 🐍 Local Python Setup (Optional)

```bash
git clone https://github.com/TudorOO/PassMan.git
cd PassMan
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Then edit .env with your own secrets

# Run the app
flask run

🐳 Docker Setup (Recommended)

If you prefer isolation and easier deployment, use Docker:
1. Clone the repository

git clone https://github.com/TudorOO/PassMan.git
cd PassMan

2. Create a .env file

Make a .env file in the root directory. Here’s an example:

SECRET_KEY=your-secret-key
ENCRYPTION_KEY=your-encryption-key
DATABASE_URL=sqlite:///db.sqlite3

3. Build the Docker image

docker build -t passman .

4. Run the container

docker run --env-file .env -p 8000:8000 passman

5. Access PassMan

Visit http://localhost:8000 in your browser.
📂 Project Structure

PassMan/
│
├── templates/          # HTML templates (Jinja2 + HTMX)
├── static/             # CSS, JS, and icons
├── webapp/             # Blueprints (auth, account, API)
├── main.py             # App entry point
├── models.py           # SQLAlchemy models
├── crypto/             # Crypto logic (AES, Argon2id)
├── requirements.txt    
├── Dockerfile          
└── .env.example        

🧠 Security Highlights

    Zero-Knowledge Encryption: Server never sees your decrypted data

    TOTP Two-Factor Auth: With QR provisioning

    Password Breach Checker: Know if your credentials have been compromised

    CSRF-Protected Forms: Everywhere

    Content Security Policy: Basic headers set

🛠️ Roadmap Ideas

    🔁 Password auto-rotation support

    🌍 Optional cloud sync (opt-in and encrypted)

    📱 PWA support (Installable web app)

    🧩 Browser extension

    🔐 YubiKey / WebAuthn integration

    🌐 Geo-fencing login protection

🤝 Contributing

Pull requests and suggestions are always welcome! Whether it's UI polish, crypto audits, or feature ideas — feel free to fork and submit a PR.
⚠️ Disclaimer

PassMan is a security-focused project developed for learning, portfolio building, and personal use. While great care was taken with encryption and security, use at your own risk in production. Security audits are welcome.
📄 License

MIT License — do what you want, just don't sell it as yours.