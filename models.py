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

    def get_notelist(self):
        notelist = []
        try:
            notelist.extend(self.notes)
        except TypeError:
            pass
        try:
            notelist.extend(self.files)
        except TypeError:
            pass
        try:
            notelist.extend(self.dirs)
        except TypeError:
            pass

        return notelist


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
    content = db.Column(
        db.Text(),
        nullable=True
    )
    preview = db.Column(
        db.String(50),
        nullable=True
    )
    create_time = db.Column(
        db.DateTime(),
        nullable=False
    )
    edit_time = db.Column(
        db.DateTime(),
        nullable=True
    )
    version = db.Column(
        db.String(64),
        nullable=False
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey('user.id'),
        nullable=False
    )
    parent_id = db.Column(
        db.String(12),
        db.ForeignKey('directory.id'),
        nullable=True
    )

    user = db.relationship(
        'User',
        backref=db.backref('notes', lazy=True)
    )
    parent = db.relationship(
        'Directory',
        backref=db.backref('notes', lazy=True)
    )

    def get_json(self):
        return {
            "id": self.id,
            "title": self.title,
            "content": self.content,
            "preview": self.preview,
            "create_time": self.create_time.timestamp(),
            "edit_time":
                self.edit_time.timestamp() if self.edit_time else None,
            "version": self.version
        }

    def delete(self):
        db.session.delete(self)

    def __repr__(self):
        return f'<Note {self.id}: {self.user.username}({self.user.id})>'


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
    mimetype = db.Column(
        db.Text(),
        nullable=True
    )
    create_time = db.Column(
        db.DateTime(),
        nullable=False
    )
    edit_time = db.Column(
        db.DateTime(),
        nullable=True
    )
    version = db.Column(
        db.String(64),
        nullable=False
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey('user.id'),
        nullable=False
    )
    parent_id = db.Column(
        db.String(12),
        db.ForeignKey('directory.id'),
        nullable=True
    )

    user = db.relationship(
        'User',
        backref=db.backref('files', lazy=True)
        )
    parent = db.relationship(
        'Directory',
        backref=db.backref('files', lazy=True)
    )

    def get_json(self):
        return {
            "id": self.id,
            "title": self.title,
            "mimetype": self.mimetype,
            "create_time": self.create_time.timestamp(),
            "edit_time":
                self.edit_time.timestamp() if self.edit_time else None,
            "version": self.version
        }

    def delete(self):
        db.session.delete(self)

    def __repr__(self):
        return f'<File {self.id}: {self.user.username}({self.user.id})>'


class Directory(db.Model):
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
    create_time = db.Column(
        db.DateTime(),
        nullable=False
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey('user.id'),
        nullable=False
    )
    parent_id = db.Column(
        db.String(12),
        db.ForeignKey('directory.id'),
        nullable=True
    )

    user = db.relationship(
        'User',
        backref=db.backref('dirs', lazy=True)
    )
    parent = db.relationship(
        'Directory',
        backref=db.backref('dirs', remote_side=[id], lazy=True)
    )

    def get_notelist(self):
        notelist = []
        try:
            notelist.extend(self.notes)
        except TypeError:
            pass
        try:
            notelist.extend(self.files)
        except TypeError:
            pass
        try:
            notelist.extend(self.dirs)
        except TypeError:
            pass

        return notelist

    def get_json(self):
        notelist = self.get_notelist()

        return {
            "id": self.id,
            "title": self.title,
            "content": [note.get_json() for note in notelist],
            "create_time": self.create_time.timestamp()
        }

    def delete(self):
        for note in self.get_notelist():
            note.delete()
        db.session.delete(self)

    def __repr__(self):
        return f'<Directory {self.id}: {self.user.username}({self.user.id})>'
