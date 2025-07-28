from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from .models import User
import requests
import hashlib
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from dotenv import load_dotenv
from webapp.auth import encrypt_aes
from webapp.views import decrypt_passkey

load_dotenv()
api = Blueprint("api", __name__)


@api.route("/api/get_breach_number", methods = ["GET", "POST"])
@login_required
def get_breach_number():
    if request.method == "POST":
        result = {}
        total = 0
        mpass = request.form.get("mpass")
        mpass = mpass.encode("utf-8")
        for key in current_user.keys:
            # Decrypt passkey using mpass
            kdf = Argon2id(
                salt=bytes.fromhex(key.salt),
                length=32,
                iterations=4,
                lanes=4,
                memory_cost=256 * 1024,
            )
            decrypk = decrypt_passkey(key.key, kdf.derive(mpass), key.app)

            # Hash and send to haveibeenpwned api
            sha_password = hashlib.sha1(decrypk).hexdigest()
            sha_postfix = sha_password[5:].upper()
            url = "https://api.pwnedpasswords.com/range/" + sha_password[0:5].upper()

            response = requests.request("GET", url, headers = {}, data = {})
            pwnd_dict = {}

            pwnd_list = response.text.split('\r\n')
            for pwnd_pass in pwnd_list:
                pwnd_hash = pwnd_pass.split(":")
                pwnd_dict[pwnd_hash[0]] = pwnd_hash[1]
            if sha_postfix in pwnd_dict.keys():
                result[key.app] = pwnd_dict[sha_password.upper()]
                total += pwnd_dict[sha_password.upper()]
            else:
                result[key.app] = 0
        data = {
            "total": total,
            "result": result
        }
        print(data)
        return jsonify(data)




# Get IV and Salt from user database
@api.route("/api/get_ivsalt", methods = ["GET", "POST"])
def get_ivsalt():
    print("Getting_Iv_Salt()")
    if request.method == "POST":
        email = request.form.get("email")
        id = request.form.get("id")
        print(email)
        print(id)
        if email != "undefined" and email != "":
            print("Getting ivsalt from email")
            user = User.query.filter_by(email = encrypt_aes(email)).first()
        elif id != -1:
            print("Getting ivsalt from id")
            user = User.query.filter_by(id = id).first()

        if user:
            return jsonify({"salt":user.salt, "iv":user.iv})
        else:
            return jsonify({"error": "User not found!"}), 404

