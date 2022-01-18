from flask import Blueprint, render_template
from flask_login import login_required, current_user

main = Blueprint('main', __name__)


@main.route('/')
def index():
    return render_template('index.html')


@main.route('/notes')
@login_required
def profile():
    return render_template('notes.html', name=current_user.name)