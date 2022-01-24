import datetime
import time
from multiprocessing.pool import ThreadPool

from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from sqlalchemy import desc
from werkzeug.security import generate_password_hash, check_password_hash

from . import db
from .input_sanitizer import validate_name, validate_password
from .models import User, Login
from flask_login import login_user, login_required, logout_user

auth = Blueprint('auth', __name__)
results = ''


def get_failed_attempts_from_last_minute(user):
    attempts = 0
    minute_ago = datetime.datetime.utcnow() - datetime.timedelta(minutes=1)
    logins_from_last_minute = Login.query.filter_by(user_id=user.id).filter(Login.date > minute_ago)\
        .order_by(desc(Login.date))
    for log in logins_from_last_minute:
        if not log.was_successful:
            attempts += 1
    return attempts


def is_blocked(user):
    last_login = Login.query.order_by(desc(Login.date)).filter_by(user_id=user.id) \
        .filter(Login.gets_blocked).first()
    if last_login is not None:
        time_delta = (datetime.datetime.utcnow() - last_login.date).total_seconds()
        print(f"Delta = {time_delta}s")
        if time_delta < 60:
            return True
    return False


def later_function():
    time.sleep(0.5)


@auth.route('/login')
def login():
    return render_template('login.html')


@auth.route('/login', methods=['POST'])
def login_post():
    ip = request.remote_addr
    name = request.form.get('name')
    password = request.form.get('password')
    user = User.query.filter_by(name=name).first()
    session.clear()
    pool = ThreadPool(processes=1)
    pool.apply(later_function)

    if not user:
        flash('Błąd logowania. Proszę spróbować ponownie.')
        return redirect(url_for('auth.login'))
    elif is_blocked(user):
        flash('Trwa blokada.')
        return redirect(url_for('auth.login'))

    elif get_failed_attempts_from_last_minute(user) >= 3:
        flash('Przekroczono limit nieudanych prób zalogowania. Proszę spróbować ponownie za minutę.')
        login_attempt = Login(user_id=user.id, ip=ip, was_successful=False, gets_blocked=True)
        db.session.add(login_attempt)
        db.session.commit()
        return redirect(url_for('auth.login'))

    elif not check_password_hash(user.password, password):
        flash('Błąd logowania. Proszę spróbować ponownie.')
        login_attempt = Login(user_id=user.id, ip=ip, was_successful=False, gets_blocked=False)
        db.session.add(login_attempt)
        db.session.commit()
        return redirect(url_for('auth.login'))

    login_user(user)
    session['user_id'] = name
    session.permanent = True
    login_attempt = Login(user_id=user.id, ip=ip,
                          was_successful=True,
                          gets_blocked=False,
                          )
    db.session.add(login_attempt)
    db.session.commit()
    return redirect(url_for('main.notes'))


@auth.route('/signup')
def signup():
    return render_template('signup.html')


@auth.route('/signup', methods=['POST'])
def signup_post():
    name = (request.form.get('name'))
    if not validate_name(name):
        flash("Niepoprawna nazwa użytkownika. Nazwa może zawierać tylko małe litery od a do z, bez polskich znaków.")
        return redirect(url_for('auth.signup'))

    password = request.form.get('password')
    password_status = validate_password(password)
    if password_status == 1:
        flash("Niepoprawne hasło. Hasło powinno składać się z od 6 do 12 znaków, zawierać małą oraz wielką "
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

    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for('auth.login'))


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))
