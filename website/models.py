from datetime import datetime, timedelta

from flask import current_app
from flask_login import UserMixin
from itsdangerous import URLSafeTimedSerializer as Serializer
from sqlalchemy import Text
from sqlalchemy.sql import func

from . import db


class Verification(db.Model):
    __tablename__ = 'verifications'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    verification_code = db.Column(db.String(6), nullable=False)
    code_expires_at = db.Column(
        db.DateTime,
        default=lambda: datetime.utcnow() + timedelta(minutes=10),
        nullable=False
    )
    is_verified = db.Column(db.Boolean, default=False, nullable=False)

    user = db.relationship('User', back_populates='verification', uselist=False)


class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    first_name = db.Column(db.String(150), nullable=False)
    #last_reset_request = db.Column(db.DateTime, nullable=True)  # Add this line
    #reset_token_used = db.Column(db.Boolean, default=False) # Add this line


    verification = db.relationship(
        'Verification',
        back_populates='user',
        uselist=False,
        cascade='all, delete-orphan'
    )

    def get_reset_token(self, expires_sec: int = 1800) -> str:
        serializer = Serializer(current_app.config['SECRET_KEY'])
        return serializer.dumps({'user_id': self.id})

    @staticmethod
    def verify_reset_token(token: str, expires_sec: int =180):
        serializer = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = serializer.loads(token, max_age=expires_sec)
        except Exception:
            return None
        user_id = data.get('user_id')
        if user_id:
            return User.query.get(data.get('user_id'))
        else:
            return None

