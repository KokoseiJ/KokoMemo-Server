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

    def __repr__(self):
        return f'<User {self.username}>'


class Note(db.Model):
    id = db.Column(
        db.String(11),
        unique=True,
        nullable=False,
        primary_key=True
    )
    title = db.Column(
        db.String(50),
        nullable=False
    )
    preview = db.Column(
        db.String(50),
        nullable=False
    )
    created_time = db.Column(
        db.BigInteger,
        nullable=False
    )
    edited_time = db.Column(
        db.BigInteger,
        nullable=True
    )
    version = db.Column(
        db.String(8),
        nullable=False
    )
    user_id = db.Column(
        db.String(50),
        db.ForeignKey("user.id"),
        nullable=False
    )
    user = db.relationship(
        'User',
        backref=db.backref(
            'notes',
            lazy=True
        )
    )

    def __repr__(self):
        return f'<Note {self.id}:{self.user.username}>'
