import flask
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

from .input_sanitizer import sanitize_text, display_text
from .models import Note, User, Share
from . import db
from sqlalchemy.orm import aliased

main = Blueprint('main', __name__)


@main.route('/')
def index():
    return render_template('index.html')


@main.route('/notes')
@login_required
def notes():
    notes = Note.query \
        .join(User, User.id == Note.user_id) \
        .add_columns(User.name, Note.id, Note.title, Note.text)\
        .filter((Note.user_id == current_user.id) | Note.is_public) \
        .all()

    shared_target_user_table = aliased(User)
    note_owner_user_table = aliased(User)
    shared_notes = Share.query \
        .filter(Share.user_id == current_user.id) \
        .join(Note, Share.note_id == Note.id) \
        .join(note_owner_user_table, note_owner_user_table.id == Note.user_id) \
        .add_columns(note_owner_user_table.name, Note.id, Note.title, Note.text) \
        .all()
    notes_list = list()
    for note in notes + shared_notes:
        note = dict(note)
        note['text'] = display_text(note['text'])
        notes_list.append(note)

    return render_template('notes.html', name=current_user.name, notes=notes_list)


@main.route('/encrypted_notes')
@login_required
def encrypted_notes():
    notes = Note.query \
        .join(User, User.id == Note.user_id) \
        .add_columns(User.name, Note.id, Note.title) \
        .filter((Note.user_id == current_user.id) & Note.is_encrypted) \
        .all()

    return render_template('encrypted_notes.html', name=current_user.name, notes=notes)


@main.route('/create_note')
@login_required
def create_note():
    return render_template('create_note.html')


@main.route('/create_note', methods=['POST'])
@login_required
def create_note_post():
    is_public = True if request.form.get('note_type') == 'public' else False
    is_encrypted = True if request.form.get('note_type') == 'encrypted' else False
    title = request.form.get('title')
    text = request.form.get('text')
    user_id = current_user.id

    new_note = Note(user_id=user_id,
                    is_public=is_public,
                    is_encrypted=is_encrypted,
                    encryption_key_hash='',
                    title=title,
                    text=sanitize_text(text))

    db.session.add(new_note)
    db.session.commit()

    return redirect(url_for('main.notes'))


@main.route('/create_encrypted_note')
@login_required
def create_encrypted_note():
    return render_template('create_encrypted_note.html')


@main.route('/create_encrypted_note', methods=['POST'])
@login_required
def create_encrypted_note_post():
    title = request.form.get('title')
    text = request.form.get('text')
    user_id = current_user.id
    password = request.form.get('encryption_password')

    # TODO: validate password requirements (force strong password)

    # double hashed password - to verify if key is correct
    # single hashed password - to be real encryption key
    # encryption_key_hash = '' if not is_encrypted else generate_password_hash(encryption_key, method='sha256')
    # encryption_key_double_hash = '' if not is_encrypted else generate_password_hash(encryption_key_hash,

    hashed_password = generate_password_hash(password, method='sha256')

    # TODO: add encryption
    encrypted_text = text

    #double_hashed_password = generate_password_hash(single_hashed_password, method='sha256')

    new_encrypted_note = Note(user_id=user_id,
                              is_public=False,
                              is_encrypted=True,
                              encryption_key_hash=hashed_password,
                              title=title,
                              text=encrypted_text)
    db.session.add(new_encrypted_note)
    db.session.commit()

    return redirect(url_for('main.encrypted_notes'))


@main.route('/decrypt_note')
@login_required
def decrypt_note():
    return render_template('decrypt_note.html')


@main.route('/decrypt_note', methods=['POST'])
@login_required
def decrypt_note_post():
    note_id = request.form.get('note_id')
    password = request.form.get('encryption_password')

    note = Note.query.filter_by(id=note_id).first()
    if note and note.is_encrypted:

        if not check_password_hash(note.encryption_key_hash, password):  # password is wrong
            flash('Nieprawidłowe hasło!')
            return redirect(url_for('main.encrypted_notes'))

        decrypted_text = note.text

        flash(decrypted_text)
        return redirect(url_for('main.decrypt_note'))

    else:
        flash('Nie znaleziono notatki')
        return redirect(url_for('main.encrypted_notes'))


@main.route('/delete_note', methods=['POST'])
@login_required
def delete_note_post():
    note_id = request.form.get('note_id')
    text = request.form.get('text')
    note = Note.query.filter_by(id=note_id).first()
    if note:
        db.session.delete(note)
        db.session.commit()

    return redirect(url_for('main.notes'))


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

    return redirect(url_for('main.notes'))


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
        return redirect(url_for('main.notes'))

    if share_user.id == current_user.id:
        flash('Nie możesz udostępnić notatki sam(a) sobie :)')
        return redirect(url_for('main.notes'))

    note = Note.query.filter_by(id=note_id).first()
    if note:

        if note.is_public:
            flash('Notatka jest już publiczna')
            return redirect(url_for('main.notes'))
        if note.user_id == share_user.id:
            flash('Nie możesz udostępnić notatki jej właścicielowi.')
            return redirect(url_for('main.notes'))
        share = Share.query.filter((note.id == Share.note_id) & (share_user.id == Share.user_id)).first()
        if not share:   # if share does not already exist
            new_share = Share(user_id=share_user.id, note_id=note.id)
            db.session.add(new_share)
            db.session.commit()
        else:   # if share already exists
            flash('Już udostępniono temu użytkownikowi')

    return redirect(url_for('main.notes'))
