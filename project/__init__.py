import os

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from os import path
from dotenv import load_dotenv
from flask_login import LoginManager

basedir = path.abspath(path.dirname(__file__))
load_dotenv(path.join(basedir, '.env'))
TESTING = True
DEBUG = True
FLASK_ENV = 'development'

db = SQLAlchemy()


def create_app():
    app = Flask(__name__)
    # this would normally be stored on a server and read by a config class
    os.environ['DEBUG'] = "1"
    os.environ['SQLALCHEMY_DATABASE_URI'] = "sqlite:///db.sqlite"
    os.environ['SESSION_COOKIE_NAME'] = "ciasteczko"
    os.environ['SECRET_KEY'] = "Ochrona2022"
    ###
    app.config.from_object('config.Config')
    db.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)
    from .models import User

    @login_manager.user_loader
    def load_user(user_id):
        # since the user_id is just the primary key of our user table, use it in the query for the user
        return User.query.get(int(user_id))

    # blueprint for auth routes in our app
    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    # blueprint for non-auth parts of app
    from .main import main as main_blueprint

    app.register_blueprint(main_blueprint)
    return app
