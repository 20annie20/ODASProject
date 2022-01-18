from flask import Blueprint, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash

from . import db
from .input_sanitizer import validate_name
from .models import User

auth = Blueprint('auth', __name__)


@auth.route('/login')
def login():
    return render_template('login.html')


@auth.route('/signup')
def signup():
    return render_template('signup.html')


# kiedy na endpoint przychodzi POST
@auth.route('/signup', methods=['POST'])
def signup_post():
    name = validate_name(request.form.get('name'))
    if name is None:
        flash("Nieprawidłowa nazwa użytkownika. Nazwa może zawierać tylko małe litery od a do z, bez polskich znaków.")
        return redirect(url_for('auth.signup'))

    password = request.form.get('password')
    # nie chcemy rejestrować użytkownika, jeśli już taki o podanej nazwie istnieje
    user = User.query.filter_by(name=name).first()
    if user:
        flash("Użytkownik o wskazanej nazwie już istnieje.")
        return redirect(url_for('auth.signup'))

    new_user = User(name=name, password=generate_password_hash(password, method='sha256', salt_length=16))

    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for('auth.login'))


@auth.route('/logout')
def logout():
    return 'Logout'
