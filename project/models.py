from project import db


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # TODO store hashes and salts of passwords instead
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
