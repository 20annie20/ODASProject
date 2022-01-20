from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from werkzeug.security import generate_password_hash, check_password_hash

from . import db
from .input_sanitizer import validate_name, validate_password
from .models import User
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint('auth', __name__)


@auth.route('/login')
def login():
    return render_template('login.html')


@auth.route('/login', methods=['POST'])
def login_post():

    name = request.form.get('name')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False
    user = User.query.filter_by(name=name).first()

    session.clear()
    session['user_id'] = name
    session.permanent = True

    if not user or not check_password_hash(user.password, password):
        flash('Błąd logowania. Proszę spróbować ponownie.')
        return redirect(url_for('auth.login'))

    login_user(user, remember=remember)
    return redirect(url_for('main.notes'))


@auth.route('/signup')
def signup():
    return render_template('signup.html')


# kiedy na endpoint przychodzi POST
@auth.route('/signup', methods=['POST'])
def signup_post():
    name = (request.form.get('name'))
    if not validate_name(name):
        flash("Nieprawidłowa nazwa użytkownika. Nazwa może zawierać tylko małe litery od a do z, bez polskich znaków.")
        return redirect(url_for('auth.signup'))

    password = request.form.get('password')
    password_status = validate_password(password)
    if password_status == 1:
        flash("Nieprawidłowe hasło. Hasło powinno składać się z od 6 do 12 znaków, zawierać małą oraz wielką "
              "literę i cyfrę")
        return redirect(url_for('auth.signup'))
    elif password_status == 2:
        flash("Użyto niedozwolonych znaków. Hasło może zawierać jedynie małe i duże litery oraz cyfry, bez polskich "
              "znaków.")
        return redirect(url_for('auth.signup'))

    # nie chcemy rejestrować użytkownika, jeśli już taki o podanej nazwie istnieje
    user = User.query.filter_by(name=name).first()
    if user:
        flash("Użytkownik o wskazanej nazwie już istnieje.")
        return redirect(url_for('auth.signup'))

    new_user = User(name=name, password=generate_password_hash(password, method='sha256', salt_length=16))

    # TODO check for possible DDoS attack - for i in some random_names'; curl na POST signupowy
    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for('auth.login'))


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))
