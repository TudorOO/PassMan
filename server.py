from flask import Flask
import os
from os import path
from webapp.extensions import db, limiter
from flask_login import LoginManager
from flask_mail import Mail
from webapp.models import User
from dotenv import load_dotenv

from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman


load_dotenv()
DB_NAME = "database.db"
csrf = CSRFProtect()
mail = Mail()


def create_app():
    app = Flask(__name__)
    Talisman(app)
    app.permanent_session_lifetime = 172800

    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_NAME}"

    app.config["MAIL_SERVER"] = os.getenv("MAIL_SERVER")
    app.config["MAIL_PORT"] = os.getenv("MAIL_PORT")
    app.config["MAIL_USE_TLS"] = True
    app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
    app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")

    limiter.init_app(app)
    db.init_app(app)
    csrf.init_app(app)
    mail.init_app(app)

    from webapp.views import views
    from webapp.auth import auth

    app.register_blueprint(views, url_prefix="/")
    app.register_blueprint(auth, url_prefix="/")

    create_database(app)

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
