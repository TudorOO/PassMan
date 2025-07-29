from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from .extensions import db
from werkzeug.security import generate_password_hash, check_password_hash
import os
import base64
import io
import qrcode
import datetime
import pyotp
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from dotenv import load_dotenv
from webapp.auth import decrypt_aes, verify_password, throw_pass_error, verify_backup_file
from webapp.views import encrypt_passkey, decrypt_passkey

load_dotenv()
dashboard = Blueprint("dashboard", __name__)

@dashboard.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard_page():
    t_update = datetime.datetime.now().replace(microsecond=0) - current_user.t_update.replace(microsecond=0)
    t_mpass_change = datetime.datetime.now().replace(microsecond=0) - current_user.t_mpass_change.replace(microsecond=0)
    return render_template("dashboard.html", user = current_user, 
    username = decrypt_aes(current_user.username), 
    time_since_last_update = t_update, 
    time_since_last_mpass_change = t_mpass_change)


