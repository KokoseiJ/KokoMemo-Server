# -*- coding: utf-8 -*-

from flask import Blueprint
from flask import request, send_file

import os
import re
import secrets
import datetime
from hashlib import sha256

from app import db
from app.module.util import return_data, token_to_user

from config import FILE_PATH
from models import Note, File, Directory


def get_noteobj(id, title, type, mimetype=None, preview=None, content=None,
                version=None):
    return {
        "id": id,
        "title": title,
        "type": type,
        "mimetype": mimetype,
        "preview": preview,
        "content": content,
        "version": version
    }


def get_preview(content):
    body_strip = re.sub("\\s", " ", content)
    return body_strip if len(body_strip) <= 50 \
        else body_strip[:47] + "..."


def get_obj(_id):
    _type = _id[0]
    if _type == "D":
        note = Directory.query.filter_by(id=_id).first()
    elif _type == "F":
        note = File.query.filter_by(id=_id).first()
    elif _type == "N":
        note = Note.query.filter_by(id=_id).first()
    else:
        note = None

    return note


bp = Blueprint(
    name=__name__.split(".")[-1],
    import_name=__name__,
    url_prefix=f"/{__name__.split('.')[-1]}"
)


@bp.route("/", methods=['GET'])
def get_every_notes():
    auth = request.headers.get("Authorization", str())
    if not auth.strip().startswith("Bearer "):
        return return_data(401, "Authorization not provided.")
    token = auth.split(" ", 1)[1]
    is_valid, user = token_to_user(token)
    if not is_valid:
        return return_data(403, user)

    notelist = user.get_notelist()

    rtnlist = [note.get_json() for note in notelist]
    return return_data(200, "", rtnlist)


@bp.route("/update", methods=['GET'])
def update_note_list():
    auth = request.headers.get("Authorization", str())
    if not auth.strip().startswith("Bearer "):
        return return_data(401, "Authorization not provided.")
    token = auth.split(" ", 1)[1]
    is_valid, user = token_to_user(token)
    if not is_valid:
        return return_data(403, user)

    data = request.get_json()
    if data is None:
        data = request.form
        if data is None:
            return return_data(400, "Data not provided.")

    notelist = user.get_notelist()

    rtnlist = [note.get_json() for note in notelist
               if note.id not in data.keys() or note.version != data[note.id]]

    return return_data(200, "", rtnlist)


@bp.route("/<_id>", methods=['GET'])
def get_note(_id):
    auth = request.headers.get("Authorization", str())
    if not auth.strip().startswith("Bearer "):
        return return_data(401, "Authorization not provided.")
    token = auth.split(" ", 1)[1]
    is_valid, user = token_to_user(token)
    if not is_valid:
        return return_data(403, user)

    _type = _id[0]

    if _type not in ["D", "F", "N"] or len(_id) != 12:
        return return_data(400, "Invalid ID.")

    if _type == "D":
        note = Directory.query.filter_by(id=_id).first()
    elif _type == "F":
        note = File.query.filter_by(id=_id).first()
    elif _type == "N":
        note = Note.query.filter_by(id=_id).first()

    if note is None:
        return return_data(404, "Note not found.")

    return return_data(200, "", note.get_json())


@bp.route("/<_id>/file", methods=['GET'])
def get_file(_id):
    auth = request.headers.get("Authorization", str())
    if not auth.strip().startswith("Bearer "):
        return return_data(401, "Authorization not provided.")
    token = auth.split(" ", 1)[1]
    is_valid, user = token_to_user(token)
    if not is_valid:
        return return_data(403, user)

    if _id[0] != "F" or len(_id) != 12:
        return return_data(400, "Invalid ID.")

    file = File.query.filter_by(id=_id).first()
    if file is None:
        return return_data(404, "File not found.")

    mimetype = file.mimetype

    return send_file(os.path.join(FILE_PATH, _id), mimetype=mimetype)


@bp.route("/", defaults={"note_path": ""}, methods=['POST'])
@bp.route("/<path:note_path>", methods=['POST'])
def create_note(note_path):
    auth = request.headers.get("Authorization", str())
    if not auth.strip().startswith("Bearer "):
        return return_data(401, "Authorization not provided.")
    token = auth.split(" ", 1)[1]
    is_valid, user = token_to_user(token)
    if not is_valid:
        return return_data(403, user)

    obj = user
    for _dir in note_path.split("/"):
        dir_list = {x.id: x for x in obj.dirs}
        if not _dir:
            continue
        elif not _dir[0] == "D":
            return return_data(400, "Invalid path.")
        obj = dir_list.get(_dir)
        if obj is None:
            return return_data(400, "Folder doesn't exist.")
    if obj is not user:
        parent = obj
    else:
        parent = None

    data = request.get_json()
    if data is None:
        data = request.form
        if data is None:
            return return_data(400, "Data not provided.")

    title = data.get('title')
    _type = data.get('type')
    content = data.get('content')
    file = request.files.get('file')
    mimetype = data.get('mimetype', 'text/plain')

    if title is None:
        return return_data(400, "Title not provided.")
    elif not isinstance(title, str):
        return return_data(400, "Title type error.")
    elif len(title) > 50:
        return return_data(400, "Title is too long.")
    elif not (isinstance(_type, str) and _type in ['D', 'F', 'N']):
        return return_data(400, "Improper type specified.")

    elif _type == 'N':
        if content is None:
            return return_data(400, "Content not provided.")
        elif not isinstance(content, str):
            return return_data(400, "Content type error.")

    elif _type == 'F':
        if file is None:
            return return_data(400, "File not specified.")
        if not isinstance(mimetype, str):
            return return_data(400, "mime_type type error.")

    id_list = [obj.id for obj in user.notes + user.files + user.dirs]
    while True:
        _id = _type + secrets.token_urlsafe(8)
        if _id not in id_list:
            break
    create_time = datetime.datetime.now()
    rtndata = {
        "id": _id,
        "type": _type,
        "title": title,
        "create_time": create_time.timestamp()
    }

    if _type != 'D':
        if _type == 'N':
            preview = get_preview(content)
            version = sha256((title + content).encode()).hexdigest()
            obj = Note(
                id=_id,
                title=title,
                content=content,
                preview=preview,
                create_time=create_time,
                version=version
            )
            rtndata.update({
                "content": content,
                "preview": preview,
                "version": version
            })
            user.notes.append(obj)
            if parent is not None:
                parent.notes.append(obj)

        elif _type == 'F':
            with open(os.path.join(FILE_PATH, _id), "wb") as f:
                file.save(f)
            with open(os.path.join(FILE_PATH, _id), "rb") as f:
                version = sha256(title.encode() + f.read()).hexdigest()
            obj = File(
                id=_id,
                title=title,
                mimetype=mimetype,
                create_time=create_time,
                version=version
            )
            rtndata.update({
                "mimetype": mimetype,
                "version": version
            })
            user.files.append(obj)
            if parent is not None:
                parent.files.append(obj)
    else:
        obj = Directory(
            id=_id,
            title=title,
            create_time=create_time
        )
        user.dirs.append(obj)
        if parent is not None:
            parent.dirs.append(obj)

    db.session.add(obj)
    db.session.commit()

    return return_data(201, "Succesfully created!", rtndata)


@bp.route("/<_id>", methods=['PATCH'])
def update_note(_id):
    auth = request.headers.get("Authorization", str())
    if not auth.strip().startswith("Bearer "):
        return return_data(401, "Authorization not provided.")
    token = auth.split(" ", 1)[1]
    is_valid, user = token_to_user(token)
    if not is_valid:
        return return_data(403, user)

    data = request.get_json()
    if data is None:
        data = request.form
        if data is None:
            return return_data(400, "Data not provided.")

    _type = _id[0]
    title = data.get("title")
    content = data.get("content")
    mimetype = data.get("mimetype")
    file = request.files.get("file")
    version = data.get("version")

    if _id[0] not in ["D", "F", "N"] or len(_id) != 12:
        return return_data(400, "Invalid ID.")

    if title is not None:
        if not isinstance(title, str):
            return return_data(400, "Title type error.")
        elif len(title) > 50:
            return return_data(400, "Title is too long.")
    if _type == "N":
        if content is not None and not isinstance(content, str):
            return return_data(400, "Content type error.")

    if _type == "F":
        if mimetype is not None and not isinstance(mimetype, str):
            return return_data(400, "Mimetype type error.")

    if _type != "D" and version is None:
        return return_data(400, "Version not provided.")

    note = get_obj(_id)
    if note is None:
        return return_data(404, "Note not found.")

    if title is not None and note.title != title:
        note.title = title

    if _type == "N":
        if content is not None and content != note.content:
            if version == note.version:
                note.content = content
            else:
                note.content += "\n\n========== On this client ==========\n\n"
                note.content += content
            note.preview = get_preview(note.content)

        hashdata = note.content.encode()

    if _type == "F":
        if file is not None:
            with open(os.path.join(FILE_PATH, _id), "wb") as f:
                file.save(f)
        with open(os.path.join(FILE_PATH, _id), "rb") as f:
            hashdata = f.read()

    if _type == "F" and mimetype is not None:
        note.mimetype = mimetype

    if _type != "D":
        version = sha256(title.encode() + hashdata).hexdigest()
        note.version = version
        note.edit_time = datetime.datetime.now()

    db.session.commit()

    return return_data(201, "Succesfully edited!", note.get_json())


@bp.route("/<_id>", methods=['DELETE'])
def delete_note(_id):
    auth = request.headers.get("Authorization", str())
    if not auth.strip().startswith("Bearer "):
        return return_data(401, "Authorization not provided.")
    token = auth.split(" ", 1)[1]
    is_valid, user = token_to_user(token)
    if not is_valid:
        return return_data(403, user)

    _type = _id[0]

    if _type not in ["D", "F", "N"] or len(_id) != 12:
        return return_data(400, "Invalid ID.")

    note = get_obj(_id)
    if note is None:
        return return_data(404, "Note not found.")

    if _type == "F":
        os.remove(os.path.join(FILE_PATH, _id))

    note.delete()
    db.session.commit()

    return return_data(200, "Succesfully deleted.")
