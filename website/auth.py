
import random
from datetime import datetime, timedelta
from functools import wraps
import smtplib
from email.mime.text import MIMEText
from flask import Blueprint, render_template, request, flash, redirect, url_for, session, make_response
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from .models import User
from .forms import ResetPasswordForm, ConfirmEmailForm

auth = Blueprint('auth', __name__)



def no_cache(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        response = make_response(view(*args, **kwargs))
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    return wrapped

def send_email(subject, body, recipient_email):
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    sender_email = "uematsuleon@gmail.com"
    sender_password = "gvyy mtur zvys hoki" 

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = recipient_email

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient_email, msg.as_string())

def send_six_digit(email, code):
    body = f"コード:\n{code}\n\n"
    send_email("６桁のコード：メールの確認", body, email)

def send_reset_email(user):
    token = user.get_reset_token()
    reset_url = url_for('auth.reset_token', token=token, _external=True)
    body = f"パスワードを更新するために、このリンクから link:\n{reset_url}\n\n　もし、パスワードリセットを希望しなかった場合は、このメールを無視して下さい。"
    send_email("Password Reset Request", body, user.email)



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
            
            return redirect(url_for('views.home'))
        elif len(email) ==0:
            flash('メールアドレスを入力して下さい','error')
        elif len(password) ==0:
            flash('パスワードを入力して下さい','error')
        else:
            flash('メールアドレスかパスワードが間違っています。', 'error')

    return render_template("login.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    response = make_response(redirect(url_for('auth.login')))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.set_cookie('session', '', expires=0)
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
            flash('既存ユーザーです。ログインして下さい。', 'error')
        elif len(email) ==0:
            flash('メールアドレスを入力して下さい','error')
        elif len(first_name) ==0:
            flash('ユーザーネームを入力して下さい','error')
        elif len(password1) ==0:
            flash('パスワードを入力してください','error')
        elif len(password2) ==0:
            flash('パスワード確認を入力して下さい','error')
        elif len(email) < 4 :
            flash('メールが短いです。', 'error')
        elif len(first_name) <2:
            flash('ユーザーネームが短い。','error')
        elif len(password1) < 7:
            flash('パスワードが弱いです。８桁以上で書いて下さい。','error')
        elif password1 != password2:
            flash('パスワードが一致していません。', 'error')
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

    if request.method == 'POST' and 'resend' in request.form:
        new_code = f"{random.randint(100000, 999999)}"
        temp_user['code'] = new_code
        session['temp_user'] = temp_user
        send_six_digit(temp_user['email'], new_code)
        flash("画面に、uematsuleon@gmail.comからメールが送られています。また、SPAM Folder を確認してください", 'success')
        return redirect(url_for('auth.confirm_email'))

    
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
