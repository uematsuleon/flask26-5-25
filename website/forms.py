from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Regexp
from .models import User

class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[
        DataRequired(message='メールアドレスを入力してください。'),
        Email(message='有効なメールアドレスを入力してください。')
    ])
    submit = SubmitField('パスワードリセットを依頼')

    def validate_email(self, field):
        user = User.query.filter_by(email=field.data).first()
        if user is None:
            raise ValidationError('このメールアドレスは登録されていません。')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('パスワード', validators=[
        DataRequired(message='パスワードを入力してください。'),
        Length(min=7, message='パスワードは7文字以上で入力してください。')
    ])
    confirm_password = PasswordField('パスワード確認', validators=[
        DataRequired(message='確認用パスワードを入力してください。'),
        EqualTo('password', message='パスワードが一致しません。')
    ])
    submit = SubmitField('パスワードをリセット')


class ConfirmEmailForm(FlaskForm):
    code = StringField('確認コード', validators=[
        DataRequired(message="コードを入力してください。"),
        Length(min=6, max=6, message="6桁のコードを入力してください。"),
        Regexp(r'^\d{6}$', message="6桁の数字を入力してください。")
    ])
    verify = SubmitField('確認')
    resend = SubmitField('再送信')

