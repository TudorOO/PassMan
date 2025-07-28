from flask import Flask
import os
from datetime import timedelta
from os import path
from webapp.extensions import db, limiter
from flask_login import LoginManager
from flask_mail import Mail
from webapp.models import User
from dotenv import load_dotenv

from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman

def CONFIG(app):
    # Base Config
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes = 30)
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_NAME}"

    # Cookie Config
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
    app.config["REMEMBER_COOKIE_DURATION"] = timedelta(seconds = 5)
    app.config["REMEMBER_COOKIE_SECURE"] = True

    # Mail Config
    app.config["MAIL_SERVER"] = os.getenv("MAIL_SERVER")
    app.config["MAIL_PORT"] = os.getenv("MAIL_PORT")
    app.config["MAIL_USE_TLS"] = True
    app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
    app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")




load_dotenv()
DB_NAME = "database.db"
csrf = CSRFProtect()
mail = Mail()

def create_app():
    app = Flask(__name__)
    csp = {
        'default-src': [
            '\'self\''
        ],
        'style-src': [
            '\'self\'',
            '\'unsafe-inline\'',
            'https://cdn.jsdelivr.net',
            'https://stackpath.bootstrapcdn.com'
        ],
        'script-src': [
            '\'self\'',
            '\'unsafe-inline\'',
            'https://cdn.jsdelivr.net',
            'https://cdnjs.cloudflare.com',
            'https://code.jquery.com',
            'https://maxcdn.bootstrapcdn.com'
        ],
        'font-src': [
            '\'self\'',
            'https://stackpath.bootstrapcdn.com'
        ],
        'img-src': [
            '\'self\'',
            'data:'
        ],
        'object-src': [
            '\'none\''
        ]
    }

    Talisman(app, content_security_policy=csp)

    # APP CONFIGURATION
    CONFIG(app)


    # Initialize all other objects using the app
    limiter.init_app(app)
    db.init_app(app)
    csrf.init_app(app)
    mail.init_app(app)

    # Register blueprints
    from webapp.views import views
    from webapp.auth import auth
    from webapp.account import account
    from webapp.api import api

    app.register_blueprint(views, url_prefix="/")
    app.register_blueprint(auth, url_prefix="/")
    app.register_blueprint(account, url_prefix="/")
    app.register_blueprint(api, url_prefix="/")

    create_database(app)

    # Login Configuration
    login_manager = LoginManager()
    login_manager.login_view = "auth.login"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))

    return app


def create_database(app):
    if not path.exists("app/" + DB_NAME):
        with app.app_context():
            db.create_all()
        print("Database intialized!")



