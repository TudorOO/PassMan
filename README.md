# 🔐 PassMan — Secure, Minimal, and Encrypted Password Manager

PassMan is a sleek, lightweight password manager built with security at its core. It leverages both **client-side** and **server-side encryption**, supports **2FA (Two-Factor Authentication)**, and allows seamless management of your credentials—all wrapped in a simple, responsive interface.

---

## 🚀 Features

- 🔑 **AES-GCM Encryption** for stored passwords  
- 🧠 **Argon2id Key Derivation** with strong salt & IV support  
- 🔐 **Client-side encryption** before transmission — zero knowledge by default  
- 🛡️ **Two-Factor Authentication (2FA)** via TOTP (Google Authenticator compatible)  
- 📦 **Backup & Restore** with encrypted recovery files  
- 📉 **Breach Detection** using [HaveIBeenPwned API]  
- 🧠 **Password Generator** with random strong key creation  
- ✨ **Modern UI** built with Bootstrap + HTMX  
- 📂 **No third-party storage** — SQLite local DB

---

## 🧪 Tech Stack

| Layer        | Technology |
|--------------|------------|
| Backend      | Flask (Python) |
| Database     | SQLite (SQLAlchemy ORM) |
| Security     | AES-GCM, Argon2id, pyotp |
| Frontend     | Bootstrap, HTMX |
| Others       | Flask-Login, Flask-WTF, dotenv, qrcode |

---

## 📸 Screenshots

<p float="left">
  <img src="assets/dashboard.png" width="47%" />
  <img src="assets/twofa.png" width="47%" />  
</p>

> 🔎 *Dashboard view* with encrypted entries and breach detection.  
> 📱 *2FA onboarding* via QR code for Google Authenticator or similar apps.

---

## ⚙️ Setup Instructions

```bash
git clone https://github.com/TudorOO/PassMan.git
cd PassMan
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
flask run
