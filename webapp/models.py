from webapp.extensions import db
from flask_login import UserMixin
from sqlalchemy.sql import func
from itsdangerous import URLSafeTimedSerializer as Serializer
from flask import current_app

#Passkey database
class Passkey(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    key = db.Column(db.String(300))
    breaches = db.Column(db.Integer, default=0)
    lastUpdate = db.Column(db.DateTime)
    salt = db.Column(db.String(200))
    app = db.Column(db.String(150))
    date = db.Column(db.DateTime(timezone = True), default = func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


#User Database
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)

    #Dashboard info
    enc_method = db.Column(db.String(30), default="AES-GCM with Argon2id derivation")
    t_update = db.Column(db.DateTime)
    t_mpass_change = db.Column(db.DateTime)
    last_login = db.Column(db.String(50), default="Unknown")


    twofa = db.Column(db.Boolean(), default = 0)
    twofa_key = db.Column(db.String(34))


    email = db.Column(db.String(150), unique = True)
    salt = db.Column(db.String(100))
    iv = db.Column(db.String(100))
    password = db.Column(db.String(150))
    username = db.Column(db.String(150))
    date = db.Column(db.DateTime(timezone = True), default = func.now())
    keys = db.relationship('Passkey')

    def get_token(self, expire_sec = 300):
        serial = Serializer(current_app.config['SECRET_KEY'])

        return serial.dumps({'user_id': self.id})

    @staticmethod
    def verify_token(token):
        print("verify token")
        print(token)
        serial = Serializer(current_app.config['SECRET_KEY'])
        try:
            user_id = serial.loads(token)
            print(user_id)
        except:  # noqa: E722
            return None
        return User.query.get(user_id['user_id'])

        


