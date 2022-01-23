import flask
import markdown
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user

from encryption import encrypt_text, decrypt_text, check_password
from .input_sanitizer import sanitize_text
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
        .filter(Note.is_encrypted == 0) \
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
        note['text'] = markdown.markdown(note['text'])
        notes_list.append(note)

    return render_template('notes.html', name=current_user.name, notes=notes_list)


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


@main.route('/encrypted_notes')
@login_required
def encrypted_notes():
    notes = Note.query \
        .join(User, User.id == Note.user_id) \
        .add_columns(User.name, Note.id, Note.title) \
        .filter((Note.user_id == current_user.id) & Note.is_encrypted) \
        .all()

    return render_template('encrypted_notes.html', name=current_user.name, notes=notes)


@main.route('/create_encrypted_note')
@login_required
def create_encrypted_note():
    return render_template('create_encrypted_note.html')


@main.route('/create_encrypted_note', methods=['POST'])
@login_required
def create_encrypted_note_post():
    title = request.form.get('title')
    text = request.form.get('text')
    text = markdown.markdown(sanitize_text(text))
    user_id = current_user.id
    password = request.form.get('encryption_password')
    encrypted_text, hashed_key, salt = encrypt_text(text, password)
    new_encrypted_note = Note(user_id=user_id,
                              is_public=False,
                              is_encrypted=True,
                              encryption_key_hash=hashed_key,
                              salt=salt,
                              title=title,
                              text=encrypted_text)
    db.session.add(new_encrypted_note)
    db.session.commit()

    return redirect(url_for('main.encrypted_notes'))


@main.route('/decrypt_note', methods=['POST'])
@login_required
def decrypt_note_post():
    note_id = request.form.get('note_id')
    password = request.form.get('encryption_password')
    note = Note.query.filter_by(id=note_id).first()
    if note and note.is_encrypted:
        if not check_password(note.encryption_key_hash, note.salt, password):  # password is wrong
            flash('Nieprawidłowe hasło!')
            return redirect(url_for('main.encrypted_notes'))
        cipher_text = note.text
        salt = note.salt
        text = decrypt_text(cipher_text, salt, password)
        decrypted_text = markdown.markdown(text)

        flash(decrypted_text)
        return render_template('decrypt_note.html', note_id=note_id)

    else:
        flash('Nie znaleziono notatki')
        return redirect(url_for('main.encrypted_notes'))


@main.route('/delete_encrypted_note', methods=['POST'])
@login_required
def delete_encrypted_note_post():
    note_id = request.form.get('note_id')
    note = Note.query.filter_by(id=note_id).first()
    if note:
        db.session.delete(note)
        db.session.commit()

    return redirect(url_for('main.encrypted_notes'))


@main.route('/delete_note', methods=['POST'])
@login_required
def delete_note_post():
    note_id = request.form.get('note_id')
    note = Note.query.filter_by(id=note_id).first()
    if note:
        db.session.delete(note)
        db.session.commit()

    return redirect(url_for('main.notes'))


@main.route('/update_note', methods=['POST'])
@login_required
def update_note_post():
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
    note.text = note.text
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
