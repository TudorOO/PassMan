from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from .extensions import db
from werkzeug.security import generate_password_hash, check_password_hash
import os
import base64
import datetime
import io
import qrcode
import pyotp
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from dotenv import load_dotenv
from webapp.auth import decrypt_aes, verify_password, throw_pass_error, verify_backup_file
from webapp.views import encrypt_passkey, decrypt_passkey

load_dotenv()
account = Blueprint("account", __name__)


# Account Route

@account.route("/account", methods = ["POST", "GET"])
@login_required
def account_page():
    print("Rendering template account.html")
    return render_template("account.html", user = current_user, username = decrypt_aes(current_user.username))


# Change Master Password Route

@account.route("/account/change_pass", methods = ["POST", "GET"])
@login_required
def change_pass():
    if request.method == "POST":
        master_password = request.form.get("master_password")
        file = request.files.get("backup-file")
        print("POST Request to /account/change_pass")
        if master_password:
            mass_hash = generate_password_hash(master_password, method="scrypt")
            print("Master hash new: " + mass_hash)
            print("Master hash old: " + current_user.password)

            print("Master salt: " + current_user.salt)
            print("Master iv: " + current_user.iv)
            if(check_password_hash(current_user.password, master_password)):
                print("Sending to change_pass, with password")
                password1 = request.form.get("pass1")
                password2 = request.form.get("pass2")
                salt = request.form.get("salt")
                iv = request.form.get("iv")
                
                if password1 != password2:
                    flash("Passwords do not match!", "error")
                else:
                    pass_check = verify_password(password1)
                    if pass_check["password_ok"]:
                        hash_pass = generate_password_hash(password1, method="scrypt")
                        reencryptKeys(password1, master_password)
                        print("Successfully re-encrypted passkeys.")
                        current_user.password = hash_pass
                        current_user.salt = salt
                        current_user.iv = iv
                        current_user.t_mpass_change = datetime.datetime.now()
                        db.session.commit()
                        return render_template("account.html", user = current_user, username = decrypt_aes(current_user.username))

                    else:
                        throw_pass_error(pass_check)
            else:
                flash("Wrong master password.", category="error")
        elif file:
            if verify_backup_file(file):
                password1 = request.form.get("pass1")
                password2 = request.form.get("pass2")
                salt = request.form.get("salt")
                iv = request.form.get("iv")
                
                if password1 != password2:
                    flash("Passwords do not match!", "error")
                else:
                    pass_check = verify_password(password1)
                    if pass_check["password_ok"]:
                        hash_pass = generate_password_hash(password1, method="scrypt")
                        current_user.keys = []
                        print("Successfully deleted passkeys.")
                        current_user.password = hash_pass
                        current_user.salt = salt
                        current_user.iv = iv
                        current_user.t_mpass_change = datetime.datetime.now()
                        db.session.commit()
                        return render_template("account.html", user = current_user, username = decrypt_aes(current_user.username))

                    else:
                        throw_pass_error(pass_check)
                return render_template("change_pass.html", user = current_user, username = decrypt_aes(current_user.username))
            else:
                flash("File provided incorrect.", category="error")
    return render_template("change_pass.html", user = current_user, username = decrypt_aes(current_user.username))


# Two Factor Authentication Disable/Enable

@account.route("/account/2fa", methods = ["POST", "GET"])
@login_required
def twofa():
    if current_user.twofa:
        # Disable User Twofa
        current_user.twofa = 0
        db.session.commit()
        return render_template("account.html", user = current_user, username = decrypt_aes(current_user.username))
    elif not current_user.twofa:
        if(request.form.get("twofa_code")):
            authCode = request.form.get("twofa_code").replace(" ", "")
            print("Got authcode: " + authCode)
            totp = pyotp.TOTP(current_user.twofa_key)
            if totp.verify(authCode):
                print("AuthCode verified")
                current_user.twofa = 1
                db.session.commit()
                return redirect(url_for("account.account_page", 
                                user = current_user, 
                                username = decrypt_aes(current_user.username)))
            else:
                print("Wrong auth code")
                flash("Wrong authentication code, please scan again!")
                qr_b64 = makeAuthQR(current_user.twofa_key)

                return render_template(
                    "twofa.html", 
                    qr_image = qr_b64, 
                    user = current_user, 
                    username = decrypt_aes(current_user.username))
        else:
            if not current_user.twofa_key:
                # Make new twofa otp key for user
                twofa_key = pyotp.random_base32(32)
                current_user.twofa_key = twofa_key
                db.session.commit()

            qr_b64 = makeAuthQR(current_user.twofa_key)
            return render_template(
                "twofa.html", 
                qr_image = qr_b64, 
                user = current_user, 
                username = decrypt_aes(current_user.username))
    else:
        return redirect(url_for("account.account_page", 
                                user = current_user, 
                                username = decrypt_aes(current_user.username)))


# Auxilary functions


    # Re-encrypt all keys using a new master password
def reencryptKeys(new_pass, old_pass):
    hash = new_pass.encode("utf-8")
    masspass = old_pass.encode("utf-8")

    for key in current_user.keys:
        # Decrypt passkey
        kdf = Argon2id(
            salt=bytes.fromhex(key.salt),
            length=32,
            iterations=4,
            lanes=4,
            memory_cost=256 * 1024,
        )
        decrypk = decrypt_passkey(key.key, kdf.derive(masspass), key.app)

        # Encrypt passkey using new password
        salt = os.urandom(50)

        kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=4,
        lanes=4,
        memory_cost=256 * 1024,
        )

        encrypt_key = kdf.derive(hash)
        ciphered_key = encrypt_passkey(
            decrypk, encrypt_key, salt, key.app
        )
        key.key = ciphered_key
        key.salt = salt.hex()
#

    # Make OTP QR Code using a twofa key(from db)
def makeAuthQR(twofa_key):
    uri = pyotp.totp.TOTP(current_user.twofa_key).provisioning_uri(name = decrypt_aes(current_user.username),
                                                                                    issuer_name = "Passman")
    qr = qrcode.make(uri)
    buffer = io.BytesIO()
    qr.save(buffer, format = "PNG")
    img_bytes = buffer.getvalue()
    return base64.b64encode(img_bytes).decode('utf-8')