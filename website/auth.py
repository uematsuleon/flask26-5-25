# Standard libraries
import random
from datetime import datetime, timedelta
from functools import wraps
import smtplib
from email.mime.text import MIMEText

# Third-party
from flask import Blueprint, render_template, request, flash, redirect, url_for, session, make_response
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# Local
from . import db
from .models import User
from .forms import ResetPasswordForm, ConfirmEmailForm

auth = Blueprint('auth', __name__)

# ------------------ Utility Decorators ------------------

def no_cache(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        response = make_response(view(*args, **kwargs))
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    return wrapped
'''
def redirect_if_logged_in(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if current_user.is_authenticated:
            return redirect(url_for('views.home'))
        return view(*args, **kwargs)
    return wrapped
'''

# ------------------ Utility Functions ------------------

def send_email(subject, body, recipient_email):
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    sender_email = "uematsuleon@gmail.com"
    sender_password = "gvyy mtur zvys hoki"  # Note: Use environment variable or app password in production!

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = recipient_email

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient_email, msg.as_string())

def send_six_digit(email, code):
    body = f"Please type this code:\n{code}\n\nIf you did not request this, ignore this message."
    send_email("6 digit code", body, email)

def send_reset_email(user):
    token = user.get_reset_token()
    reset_url = url_for('auth.reset_token', token=token, _external=True)
    body = f"To reset your password, visit the following link:\n{reset_url}\n\nIf you didn't request this, ignore this email."
    send_email("Password Reset Request", body, user.email)

# ------------------ Routes ------------------

@auth.route('/')
def auth_index():
    return redirect(url_for('auth.login'))

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            flash('ログイン成功', 'success')
            login_user(user, remember=False)
            #session['user_id'] = user.id
            return redirect(url_for('views.home'))
        flash('メールアドレスかパスワードが間違っています。', 'error')

    return render_template("login.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    print("logout_user() called")
    session.clear()
    print("session.clear() called")
    response = make_response(redirect(url_for('auth.login')))
    print(f"Redirecting to: {url_for('auth.login')}")
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.set_cookie('session', '', expires=0)
    print("Response headers set")
    flash('ログアウトしました', 'success')
    return response




@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('メールは既に使われています。', 'error')
        elif len(email) < 4 or len(first_name) < 2 or len(password1) < 7:
            flash('入力内容に誤りがあります。', 'error')
        elif password1 != password2:
            flash('パスワードが一致しません。', 'error')
        else:
            code = f"{random.randint(100000, 999999)}"
            session['temp_user'] = {
                'email': email,
                'password': password1,
                'first_name': first_name,
                'code': code
            }
            send_six_digit(email, code)
            flash('メール送信しました。','success')
            return redirect(url_for('auth.confirm_email'))

    return render_template("sign_up.html", user=current_user)

@auth.route('/confirm-email', methods=['GET', 'POST'])
def confirm_email():
    form = ConfirmEmailForm()
    temp_user = session.get('temp_user')
    count = session.get('verify_fail_count', 0)

    if not temp_user:
        flash("セッションの有効期限が切れました。", 'error')
        return redirect(url_for('auth.sign_up'))

    # Resend button pressed
    if request.method == 'POST' and 'resend' in request.form:
        new_code = f"{random.randint(100000, 999999)}"
        temp_user['code'] = new_code
        session['temp_user'] = temp_user
        send_six_digit(temp_user['email'], new_code)
        flash("確認コードを再送信しました。", 'success')
        return redirect(url_for('auth.confirm_email'))  # Refresh page to clear POST

    # Verify button pressed
    if form.validate_on_submit() and 'verify' in request.form:
        if str(form.code.data) == str(temp_user['code']):
            try:
                new_user = User(
                    email=temp_user['email'],
                    first_name=temp_user['first_name'],
                    password=generate_password_hash(temp_user['password'], method='pbkdf2:sha256')
                )
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user, remember=True)
                session.pop('temp_user', None)
                session.pop('verify_fail_count', None)
                flash("メール確認完了！ログインしました。", 'success')
                return redirect(url_for('views.home'))
            except Exception as e:
                db.session.rollback()
                flash("エラーが発生しました。", 'error')
        else:
            flash("コードが合ってません。", 'error')
            count += 1
            session['verify_fail_count'] = count
            if count >= 4:
                session.pop('verify_fail_count', None)
                return redirect(url_for('auth.login'))

    return render_template("confirm_email.html", user=current_user, form=form)

@auth.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    email = None
    if request.method == 'POST':

        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            send_reset_email(user)
            flash('パスワードリセットリンクを送信しました。', 'success')
        else:
            flash('そのメールアドレスは登録されていません。', 'error')

    return render_template('reset_password.html', user=current_user,email = email)

@auth.route("/reset-password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    user = User.verify_reset_token(token)
    if not user:
        flash('無効または期限切れのトークンです。', 'error')
        return redirect(url_for('auth.reset_password'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        try:
            user = db.session.get(User, user.id)
            user.password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
            db.session.commit()
            flash('パスワードが更新されました。', 'success')
            login_user(user, remember=True)

            flash("メール確認完了！ログインしました。", 'success')
            count = 0
            return redirect(url_for('views.home'))

        except Exception as e:
            db.session.rollback()
            flash('エラーが発生しました。', 'error')

    return render_template('reset_token.html', form=form)