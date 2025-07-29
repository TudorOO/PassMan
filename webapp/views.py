from flask import Blueprint, render_template, request, flash, send_file
from flask_login import login_required, current_user
from .extensions import db
from .models import Passkey
from werkzeug.security import check_password_hash
import os
import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from base64 import urlsafe_b64encode, urlsafe_b64decode
from dotenv import load_dotenv
from webapp.auth import decrypt_aes


load_dotenv()
views = Blueprint("views", __name__)

# Reencrypt passkeys using new master password
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


# Create new passkey from master_password + app
def create_passkey(app, mpass):
    random_key = os.urandom(32)
    salt = os.urandom(50)

    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=4,
        lanes=4,
        memory_cost=256 * 1024,
    )

    encrypt_key = kdf.derive(mpass.encode("utf-8"))
    ciphered_key = encrypt_passkey(
        random_key, encrypt_key, salt, app
    )
    passkey = Passkey(
        app=app,
        key=ciphered_key,
        user_id=current_user.id,
        salt=salt.hex(),
    )

    current_user.t_update = datetime.datetime.now()

    db.session.add(passkey)
    db.session.commit()
    flash("Passkey created successfully!", "success")


# ENCRYPTION/DECRYPTION AESGCM
def encrypt_passkey(raw, enc_key, salt, app):
    aesgcm = AESGCM(enc_key)
    nonce = os.urandom(12)
    aad = f"{current_user.id}:{app}".encode("utf-8")
    encrypted_passkey = aesgcm.encrypt(nonce, raw, aad)
    return urlsafe_b64encode(nonce + encrypted_passkey).decode("utf-8")

def decrypt_passkey(encrypted_str, encryption_key, app):
    data = urlsafe_b64decode(encrypted_str.encode("utf-8"))
    nonce, ciphertext = data[:12], data[12:]
    aesgcm = AESGCM(encryption_key)
    aad = f"{current_user.id}:{app}".encode("utf-8")
    decrypted = aesgcm.decrypt(nonce, ciphertext, aad)
    return decrypted



# Download backup file
@views.route("/download")
@login_required
def download():
    path = "webapp/keybackups/key_" + str(current_user.id) + ".json"
    if os.path.isfile(path):
        return send_file(path, as_attachment=True)
    else:
        flash("Backup key not generated. Please try again!")


# Search for specific passkey(HTMX)
@views.route("/search")
@login_required
def search():
    q = request.args.get("q")
    print(q)

    if q:
        result = (
            Passkey.query.filter_by(user_id=current_user.id)
            .filter(Passkey.app.icontains(q))
            .limit(100)
            .all()
        )
    else:
        result = Passkey.query.filter_by(user_id=current_user.id).limit(20).all()
    return render_template("search_results.html", results=result)


# Home Tab
@views.route("/home", methods=["POST", "GET"])
@login_required
def home():
    if request.method == "POST":
        if request.form["submit_button"] == "New Passkey":  # MAKE NEW PASSKEY
            app = request.form.get("app")
            mpass = request.form.get("mpass")

            if check_password_hash(current_user.password, mpass):
                if app:
                    if Passkey.query.filter_by(
                        app=app, user_id=current_user.id
                    ).first():  # Check if app already listed
                        flash("Passkey already created for " + app)
                    else:
                        # Create random key
                        # Encrypt using master password + salt
                        # Store key as Passkey object linked to user object.
                        create_passkey(app, mpass)
            else:
                flash("Wrong master password!", category="error")

        elif request.form["submit_button"][0] == "D":  # DELETE PASSKEY
            pass_id = int(request.form["submit_button"][1:])
            masspass = request.form.get("mpass")

            if check_password_hash(current_user.password, masspass):
                passkey = Passkey.query.filter_by(
                    id=pass_id, user_id=current_user.id
                ).first()
                current_user.t_update = datetime.datetime.now()
                db.session.delete(passkey)
                db.session.commit()

        elif request.form["submit_button"][0] == "R":  # DECRYPT PASSKEY
            pass_id = int(request.form["submit_button"][1:])
            masspass = request.form.get("mpass")

            if check_password_hash(current_user.password, masspass):
                masspass = masspass.encode("utf-8")
                Pass = Passkey.query.filter_by(
                    id=pass_id, user_id=current_user.id
                ).first()
                kdf = Argon2id(
                    salt=bytes.fromhex(Pass.salt),
                    length=32,
                    iterations=4,
                    lanes=4,
                    memory_cost=256 * 1024,
                )
                decrypk = decrypt_passkey(Pass.key, kdf.derive(masspass), Pass.app)
                return render_template(
                    "home.html",
                    user=current_user,
                    passes=current_user.keys,
                    decrypt=pass_id,
                    decrypt_key="#A" + decrypk.hex(),
                )

            else:
                flash("Incorrect master password", "error")

        elif request.form["submit_button"][0] == "H":  # ENCRYPT PASSKEY
            pass
    return render_template(
        "home.html", user=current_user, passes=current_user.keys, decrypt=-1, username = decrypt_aes(current_user.username)
    )

# Landing Page
@views.route("/")
@views.route("/land")
def land():
    if current_user.is_authenticated:
        return render_template("land.html", user=current_user,  username = decrypt_aes(current_user.username))
    else:
        return render_template("land.html", user=current_user)
