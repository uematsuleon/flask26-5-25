from functools import wraps
from flask import Blueprint, render_template, request, flash, redirect, url_for, make_response, jsonify
from flask_login import login_required, current_user
from . import db
from .models import Note

views = Blueprint('views', __name__)

def no_cache(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        resp = make_response(f(*args, **kwargs))
        headers = {
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'
        }
        resp.headers.update(headers)
        return resp
    return decorated






@views.route('/home', methods=['GET', 'POST'])
@login_required
@no_cache
def home():
    if request.method == 'POST':
        note_text = request.form.get('note', '').strip()
        if not note_text:
            flash('Note is too short!', 'error')
        else:
            new_note = Note(data=note_text, user_id=current_user.id)
            db.session.add(new_note)
            db.session.commit()
            flash('Note added!', 'success')

    # Fetch current user's notes, most recent first
    notes = (
        Note.query
        .filter_by(user_id=current_user.id)
        .order_by(Note.date.desc())
        .all()
    )
    return render_template('home.html', user=current_user, notes=notes)


@views.route('/delete-note', methods=['POST'])
@login_required
def delete_note():
    data = request.get_json() or {}
    note_id = data.get('noteId')
    note = Note.query.get(note_id)

    if note and note.user_id == current_user.id:
        db.session.delete(note)
        db.session.commit()
        return jsonify({'success': True})

    return jsonify({'success': False}), 404