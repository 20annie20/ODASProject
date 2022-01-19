import flask
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user
from werkzeug.security import generate_password_hash

from .input_sanitizer import sanitize_text, display_text
from .models import Note, User, Share
from . import db
from sqlalchemy.orm import aliased

main = Blueprint('main', __name__)


@main.route('/')
def index():
    return render_template('index.html')


@main.route('/profile')
@login_required
def profile():
    notes = Note.query \
        .join(User, User.id == Note.user_id) \
        .add_columns(User.name, Note.id, Note.text)\
        .filter((Note.user_id == current_user.id) | Note.is_public) \
        .all()

    shared_target_user_table = aliased(User)
    note_owner_user_table = aliased(User)
    shared_notes = Share.query \
        .filter(Share.user_id == current_user.id) \
        .join(Note, Share.note_id == Note.id) \
        .join(note_owner_user_table, note_owner_user_table.id == Note.user_id) \
        .add_columns(note_owner_user_table.name, Note.id, Note.text) \
        .all()
    notes_list = list()
    for note in notes + shared_notes:
        note = dict(note)
        note['text'] = display_text(note['text'])
        notes_list.append(note)

    return render_template('profile.html', name=current_user.name, notes=notes_list)


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
                    text=sanitize_text(text))

    db.session.add(new_note)
    db.session.commit()

    return redirect(url_for('main.profile'))


@main.route('/delete_note', methods=['POST'])
@login_required
def delete_note_post():
    note_id = request.form.get('note_id')
    text = request.form.get('text')
    note = Note.query.filter_by(id=note_id).first()
    if note:
        db.session.delete(note)
        db.session.commit()

    return redirect(url_for('main.profile'))


@main.route('/update_note', methods=['POST'])
@login_required
def update_note_post():
    # TODO get the original text of the note
    note_id = request.form.get('note_id')
    text = request.form.get('text')
    note = Note.query.filter_by(id=note_id).first()
    if note:
        note.text = sanitize_text(text)
        db.session.commit()

    return redirect(url_for('main.profile'))


@main.route('/edit_note', methods=['POST'])
@login_required
def edit_note_post():
    note_id = request.form.get('note_id')
    note = Note.query.filter_by(id=note_id).first()
    note.text = display_text(note.text)
    return render_template('update_note.html', note=note)


@main.route('/share_note', methods=['POST'])
@login_required
def share_note_post():
    note_id = request.form.get('note_id')
    share_user_name = request.form.get('share_user_name')

    share_user = User.query.filter_by(name=share_user_name).first()

    if not share_user:
        flash(f'Nie znaleziono użytkownika: {share_user_name}')
        return redirect(url_for('main.profile'))

    if share_user.id == current_user.id:
        flash('Nie możesz udostępnić notatki sam(a) sobie :)')
        return redirect(url_for('main.profile'))

    note = Note.query.filter_by(id=note_id).first()
    if note:

        if note.is_public:
            flash('Notatka jest już publiczna')
            return redirect(url_for('main.profile'))
        if note.user_id == share_user.id:
            flash('Nie możesz udostępnić notatki jej właścicielowi.')
            return redirect(url_for('main.profile'))
        share = Share.query.filter((note.id == Share.note_id) & (share_user.id == Share.user_id)).first()
        if not share:   # if share does not already exist
            new_share = Share(user_id=share_user.id, note_id=note.id)
            db.session.add(new_share)
            db.session.commit()
        else:   # if share already exists
            flash('Już udostępniono temu użytkownikowi')

    return redirect(url_for('main.profile'))