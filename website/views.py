from functools import wraps
from flask import Blueprint, render_template, request, flash, redirect, url_for, make_response, jsonify
from flask_login import login_required, current_user
from . import db
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
    return render_template('home.html', user=current_user)


