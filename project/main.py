from flask import Blueprint, render_template, redirect, url_for
from flask_login import login_required, current_user

main = Blueprint('main', __name__)


@main.route('/')
def index():
    return render_template('index.html')


@main.route('/notes')
@login_required
def profile():
    return render_template('notes.html', name=current_user.name)


@main.route('/create_note')
@login_required
def notes():
    return render_template('create_note.html')