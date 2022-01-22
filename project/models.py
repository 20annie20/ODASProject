from project import db
from flask_login import UserMixin


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    is_public = db.Column(db.Boolean)
    is_encrypted = db.Column(db.Boolean)
    encryption_key_hash = db.Column(db.String(100))
    title = db.Column(db.String(100))
    text = db.Column(db.String(1000))


class Share(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    note_id = db.Column(db.Integer)


class Login(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    date = db.Column(db.Date)
