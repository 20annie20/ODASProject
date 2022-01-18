from project import db
from flask_login import UserMixin


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # TODO store hashes and salts of passwords instead
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
