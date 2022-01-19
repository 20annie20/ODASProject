from flask import Blueprint, render_template, redirect, url_for, request
from flask_login import login_required, current_user
from werkzeug.security import generate_password_hash
from .models import Note, User
from . import db

main = Blueprint('main', __name__)


@main.route('/')
def index():
    return render_template('index.html')


@main.route('/profile')
@login_required
def profile():
    notes = Note.query \
        .join(User, User.id == Note.user_id) \
        .add_columns(User.name, Note.id, Note.text) \
        .filter((Note.user_id == current_user.id) | Note.is_public) \
        .all()

    return render_template('profile.html', name=current_user.name, notes=notes)


@main.route('/create_note')
@login_required
def create_note():
    return render_template('create_note.html')


@main.route('/create_note', methods=['POST'])
@login_required
def create_note_post():
    is_public = True if request.form.get('note_type') == 'public' else False
    is_encrypted = True if request.form.get('note_type') == 'encrypted' else False
    # encryption_key = request.form.get('encryption_key')
    text = request.form.get('text')
    user_id = current_user.id

    # TODO: validate input

    # double hashed key - to verify if key is correct
    # single hashed key - to be real encryption key
    # encryption_key_hash = '' if not is_encrypted else generate_password_hash(encryption_key, method='sha256')
    # encryption_key_double_hash = '' if not is_encrypted else generate_password_hash(encryption_key_hash,
    #                                                                                 method='sha256')
    # if is_encrypted:
    #     # TODO: add encryption
    #     pass

    new_note = Note(user_id=user_id,
                    is_public=is_public,
                    is_encrypted=is_encrypted,
                    encryption_key_hash='',
                    text=text)

    db.session.add(new_note)
    db.session.commit()

    return redirect(url_for('main.profile'))


@main.route('/delete_note', methods=['POST'])
@login_required
def delete_note_post():
    note_id = request.form.get('note_id')

    note = Note.query.filter_by(id=note_id).first()
    if note:
        db.session.delete(note)
        db.session.commit()

    return redirect(url_for('main.profile'))


@main.route('/edit_note', methods=['POST'])
@login_required
def edit_note_post():
    note_id = request.form.get('note_id')
    text = request.form.get('text')

    note = Note.query.filter_by(id=note_id).first()
    if note:
        note.text = text
        db.session.commit()

    return redirect(url_for('main.profile'))
