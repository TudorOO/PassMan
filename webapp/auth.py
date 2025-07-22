from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from flask_login import login_user, login_required, logout_user, current_user
from flask_mail import Message
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from server import mail
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import re
import json
import base64
from dotenv import load_dotenv
from webapp.extensions import db, limiter


auth = Blueprint("auth", __name__)
load_dotenv()


# Encrypt/Decrypt for metadata(email, name, etc.)
def encrypt_aes(data):
    print("Encrypting data:" + data)
    aesgcm = AESGCM(os.getenv("AESGCM_META_KEY").encode())
    nonce = "knmskcilrnd".encode()
    key = aesgcm.encrypt(nonce, data.encode(), None)
    return key
def decrypt_aes(data):
    aesgcm = AESGCM(os.getenv("AESGCM_META_KEY").encode())
    nonce = "knmskcilrnd".encode()
    key = aesgcm.decrypt(nonce, data, None)
    return key.decode()


# Throw password error
def throw_pass_error(pass_check):
    if pass_check["length_error"]:
        flash("Password too short!")
    if pass_check["digit_error"]:
        flash("Password must contain a digit")
    if pass_check["uppercase_error"]:
        flash("Password must contain a uppercase letter")
    if pass_check["lowercase_error"]:
        flash("Password must contain a lowercase letter")
    if pass_check["symbol_error"]:
        flash("Password must contain a special symbol(#$%^@#!)")


# Send password reset mail
def send_mail(user):
    token = user.get_token()

    # Email message
    msg = Message(
        "Password Reset Request", recipients=[decrypt_aes(user.email)], sender="noreply@passman.com"
    )
    msg.body = f""" You have requested a password reset for PassMan password manager.
    To reset your password, plese follow the link below.

    {url_for("auth.reset_token", token=token, _external=True)}

    If you didn't request this reset, please message us at passman636@gmail.com!

    """
    mail.send(msg)


# Generate backup file for No-Pass Login
def generate_backup_file(pass1):
    # Derive key using Argon2ID from the master password
    salt = os.urandom(50)
    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=4,
        memory_cost=256 * 1024,
        lanes=2,
    )
    derived_key = kdf.derive(pass1.encode())

    # Encrypt AESGCM_CHECK_KEY using AESGCM with the derived key
    aesgcm = AESGCM(derived_key)
    nonce = os.urandom(12)
    ciphered_key = aesgcm.encrypt(nonce, os.getenv("AESGCM_CHECK_KEY").encode(), None)

    # Generate backup file data
    backup = {
        "nonce": base64.b64encode(nonce).decode(),
        "salt": base64.b64encode(salt).decode(),
        "derive_key": base64.b64encode(derived_key).decode(),
        "check_key": base64.b64encode(ciphered_key).decode(),
    }
    return backup


# Verify password strength
def verify_password(p):
    length_error = len(p) < 8  # Minim 8 caractere
    digit_error = re.search(r"\d", p) is None  # Minim o cifra
    uppercase_error = re.search(r"[A-Z]", p) is None  # Minim o litera mare
    lowercase_error = re.search(r"[a-z]", p) is None  # Minim o litera mica
    symbol_error = re.search("~!@#$%^&*_+=}]?><|", p) is None  # Minim un simbol

    password_ok = not (
        length_error
        or digit_error
        or uppercase_error
        or lowercase_error
        or symbol_error
    )

    return {
        "password_ok": password_ok,
        "length_error": length_error,
        "digit_error": digit_error,
        "uppercase_error": uppercase_error,
        "lowercase_error": lowercase_error,
        "symbol_error": symbol_error,
    }


# Logout route
@auth.route("/logout")
@login_required
def logout():
    session.clear()
    logout_user()
    return redirect(url_for("auth.login"))


# Login route
@limiter.limit("5 per minute")
@auth.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        file = request.files.get("backup-file")
        
        user = User.query.filter_by(email=encrypt_aes(email)).first()

        if user:
            # Password Login
            if password:
                if check_password_hash(user.password, password):
                    flash("Logged in successfully!", category="success")
                    login_user(user, remember=True)
                    return redirect(url_for("views.home"))

                else:
                    flash("Incorrect password, try again.", category="error")
            # Backup file Login
            if file:
                # Load data from Backup File
                data = json.load(file)
                nonce = base64.b64decode(data["nonce"])
                check_key = base64.b64decode(data["check_key"])
                dkey = base64.b64decode(data["derive_key"])

                # Decrypt derived key using the check key(both in backup file)
                aesgcm = AESGCM(dkey)
                enc_hash = aesgcm.decrypt(nonce, check_key, None)

                # Compare the decrypted key with AESGCM_CHECK_KEY
                if enc_hash.decode() == os.getenv("AESGCM_CHECK_KEY"):
                    flash("Logged in successgully!", category="success")
                    login_user(user, remember=True)
                    return redirect(url_for("views.home"))

                else:
                    flash("File provided incorrect.", category="error")

        else:
            flash("No account registered on that email!", category="error")
    return render_template("login.html", user=current_user)


# Register Route
@limiter.limit("5 per hour")
@auth.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email")
        firstName = request.form.get("firstName")
        pass1 = request.form.get("password1")
        pass2 = request.form.get("password2")

        user = User.query.filter_by(email=encrypt_aes(email)).first()

        # Verify register input
        if user:  # One account per email
            flash("Email already has a registered account!", category="error")
        elif len(email) < 4:  # Email length > 4
            flash("Email must be greater than 4 characters! ", category="error")
        elif len(firstName) < 2:  # First name length > 2
            flash("First name too short! ", category="error")
        elif pass1 != pass2:
            flash("Passwords do not match!", category="error")
        else:
            pass_check = verify_password(pass1)
            if pass_check["password_ok"]:
                hashpass = generate_password_hash(pass1, method="scrypt")

                # Create new user
                new_user = User(
                    email=encrypt_aes(email),
                    first_name=encrypt_aes(firstName),
                    password=hashpass,
                    salt=os.urandom(50),
                )

                # Add user to database and login
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user, remember=True)

                # Generate backup data
                backup = generate_backup_file(pass1)

                # Generate backup file
                root = os.path.realpath(__file__)[:-len(os.path.basename(__file__))]
                with open(
                    root + "keybackups/key_"
                    + str(new_user.id)
                    + ".json",
                    "w",
                ) as file_out:
                    json.dump(backup, file_out)

                flash("Account created!", category="success")
                return redirect(url_for("views.home"))
            else:
                throw_pass_error(pass_check)
    return render_template("register.html", user=current_user)


# Password reset form route
@limiter.limit("10 per hour")
@auth.route("/reset", methods=["GET", "POST"])
def reset():
    if request.method == "POST":
        email = request.form.get("email")
        user = User.query.filter_by(email=encrypt_aes(email)).first()

        if user:
            send_mail(user)

        flash(
            "If there is an account linked to the email address, you will recieve a link to reset your password (valid for 5 minutes), ",
            "success",
        )
        return redirect(url_for("auth.login"))
    return render_template("reset.html", user=current_user)


# Password reset route
@limiter.limit("5 per hour")
@auth.route("/reset/<token>", methods=["GET", "POST"])
def reset_token(token):
    user = User.verify_token(token=token)
    if user is None:
        flash("Invalid token", "error")
        return redirect(url_for("auth.reset"))
    else:
        if request.method == "POST":
            pass1 = request.form.get("password1")
            pass2 = request.form.get("password2")
            if pass1 != pass2:
                flash("Passwords do not match!", "error")
            else:
                pass_check = verify_password(pass1)
                if pass_check["password_ok"]:
                    user.password = generate_password_hash(pass1, method="scrypt")
                    db.session.commit()
                    flash("Password reseted succesfully!", "success")
                    return redirect(url_for("auth.login"))
                else:
                    throw_pass_error(pass_check)
        return render_template("change_pass.html", user=current_user)
