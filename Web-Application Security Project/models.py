from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
#from cryptography.fernet import Fernet

db = SQLAlchemy()

# Master user/account variables (password is stored as hash)(key is stored encrypted)
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(16), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    key = db.Column(db.String(128), nullable=False)
    mfa_enabled = db.Column(db.Boolean, default=False)

# User credentials list variables
class Credential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    website = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)