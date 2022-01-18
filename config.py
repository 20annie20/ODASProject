from os import environ
SQLALCHEMY_DATABASE_URI = environ.get('SQLALCHEMY_DATABASE_URI')
SECRET_KEY = environ.get('SECRET_KEY')


class Config:
    """Base config."""
    SECRET_KEY = environ.get('SECRET_KEY')
    # TODO use to determine logged user?
    # SESSION_COOKIE_NAME = environ.get('SESSION_COOKIE_NAME')
    STATIC_FOLDER = 'static'
    TEMPLATES_FOLDER = 'templates'
    SQLALCHEMY_DATABASE_URI = environ.get('SQLALCHEMY_DATABASE_URI')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    FLASK_ENV = 'development'
    DEBUG = True
    TESTING = True
