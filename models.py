# -*- coding: utf-8 -*-

from app import db


class User(db.Model):
    id = db.Column(
        db.Integer,
        unique=True,
        nullable=False,
        primary_key=True
    )
    username = db.Column(
        db.String(50),
        unique=True,
        nullable=False
    )
    password = db.Column(
        db.String(60),
        nullable=False
    )
    email = db.Column(
        db.String(50),
        unique=True,
        nullable=False
    )
    nickname = db.Column(
        db.String(50),
        nullable=False
    )
    recent_token_issued_time = db.Column(
        db.BigInteger,
        nullable=True
    )

    def __repr__(self):
        return f'<User {self.username}>'
