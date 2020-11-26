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


class Note(db.Model):
    id = db.Column(
        db.String(12),
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
    content =  db.Column(
        db.String(),
        nullable=False
    )
    version = db.Column(
        db.String(8),
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
    parent_id = db.Column(
        db.String(12),
        db.ForeignKey("Folder.id"),
        nullable=True
    )
    parent = db.relationship(
        'Folder',
        backref=db.backref(
            'contents',
            lazy=True
        )
    )
    user_id = db.Column(
        db.Integer,
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

class File(db.Model):
    id = db.Column(
        db.String(12),
        unique=True,
        nullable=False,
        primary_key=True
    )
    title = db.Column(
        db.String(50),
        nullable=False
    )
    desc = db.Column(
        db.String(50),
        nullable=False
    )
    content =  db.Column(
        db.Bytes,
        nullable=False
    )
    version = db.Column(
        db.String(8),
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
    parent_id = db.Column(
        db.String(12),
        db.ForeignKey("Folder.id"),
        nullable=True
    )
    parent = db.relationship(
        'Folder',
        backref=db.backref(
            'contents',
            lazy=True
        )
    )
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )
    user = db.relationship(
        'User',
        backref=db.backref(
            'files',
            lazy=True
        )
    )

    def __repr__(self):
        return f'<File {self.id}:{self.user.username}>'

class Folder(db.Model):
    id = db.Column(
        db.String(12),
        unique=True,
        nullable=False,
        primary_key=True
    )
    title = db.Column(
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
    user_id = db.Column(
        db.String(50),
        db.ForeignKey("user.id"),
        nullable=False
    )
    user = db.relationship(
        'User',
        backref=db.backref(
            'folders',
            lazy=True
        )
    )

    def __repr__(self):
        return f'<Folder {self.id}:{self.user.username}>'
