# -*- coding: utf-8 -*-

from flask import Blueprint
from flask import request, send_file, make_response

import io
import os
import re
import json
import time
import secrets

from app import db
from app.module.b64 import check_b64, b64encode, b64decode
from app.module.util import return_data, token_to_user

from config import PATH


def get_list(path):
    '''
    return [json.loads(read_file(file.path)) if file.is_file()
            else {
                "title": file.name,
                "type": "D",
                "content": get_list(file.path),
                "version": None
            } for file in os.scandir(path) if check_b64(file.name[1:])]
    '''
    filelist = []
    for file in os.scandir(path):
        if file.name[0] not in ["D", "F", "N"] or\
                not check_b64(file.name[1:]) or len(file.name) != 12:
            continue
        if file.is_file():
            with open(file.path) as f:
                data = json.load(f)
            data['content'] = None
            filelist.append(data)
        else:
            with open(os.path.join(file.path, "_title")) as f:
                title = f.read()
            filelist.append({
                "id": file.name,
                "title": title,
                "type": "D",
                "mimetype": None,
                "preview": None,
                "content": get_list(file.path),
                "version": None
            })
    return filelist


bp = Blueprint(
    name=__name__.split(".")[-1],
    import_name=__name__,
    url_prefix=f"/{__name__.split('.')[-1]}"
)


@bp.route('/list', methods=['GET'])
def get_note_list():
    auth = request.headers.get("Authorization", str())
    if not auth.strip().startswith("Bearer "):
        return return_data(401, "Auhorization not provided.")
    token = auth.split(" ", 1)[1]
    is_valid, user = token_to_user(token)
    if not is_valid:
        return return_data(403, user)

    data = get_list(os.path.join(PATH, "notes", str(user.id)))

    return return_data(200, data=data)


@bp.route('/', defaults={'note_path': ""}, methods=['POST'])
@bp.route('/<path:note_path>', methods=['POST'])
def upload_note(note_path):
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

    title = data.get("title")
    _type = data.get("type")
    content = data.get("content")
    file = request.files.get("file")

    id_list_path = os.path.join(PATH, "notes", str(user.id), "_id_list")
    with open(id_list_path) as f:
        id_list = f.read().split(",")
    if False in [check_b64(path) and path in id_list
                 for path in note_path.split("/")]:
        return return_data(400, "Path is invalid.")

    if title is None:
        return return_data(400, "Title not provided.")
    if len(title) >= 50:
        return return_data(400, "Title is too long.")
    if _type not in ["N", "F", "D"]:
        return return_data(400, "Wrong type specified.")
    if _type == "N" and content is None:
        return return_data(400, "Content not provided.")
    if _type == "F":
        if file is None:
            return return_data(400, "File content not provided.")

    while True:
        _id = _type + secrets.token_urlsafe(8)
        if _id not in id_list:
            break

    user_path = os.path.join(PATH, "notes", str(user.id))
    if _type == "D":
        try:
            fpath = os.path.join(user_path, note_path, _id)
            os.mkdir(fpath)
        except (FileExistsError, PermissionError):
            return return_data(500, "Failed to create a folder.\n"
                                    "This is server-side error and "
                                    "should not happen at all.\n"
                                    "Please contact administrator for help.")
        with open(os.path.join(fpath, "_title"), "w") as f:
            f.write(title)

        data = {
            "id": _id,
            "title": title,
            "type": "D",
            "mimetype": None,
            "preview": None,
            "content": None,
            "version": None
        }
    else:
        version = secrets.token_hex(4) if _type in ["N", "F"] else None
        if _type == "N":
            mimetype = None
            body_strip = re.sub("\\s", " ", content)
            preview = body_strip if len(body_strip) <= 50 \
                else body_strip[:47] + "..."
        elif _type == "F":
            mimetype = data.get("mimetype")
            if mimetype is None:
                mimetype = "application/octet-stream"
            preview = None
            f = io.BytesIO()
            file.save(f)
            content = b64encode(f.getvalue()).decode()

        data = {
            "id": _id,
            "title": title,
            "type": _type,
            "mimetype": mimetype,
            "preview": preview,
            "content": content,
            "version": version
        }
        with open(os.path.join(user_path, note_path, _id), "w") as f:
            f.write(json.dumps(data))

    with open(id_list_path, "a") as f:
        f.write(_id + ",")

    return return_data(201, "Successfully uploaded!", data)


@bp.route('/<path:note_path>', methods=['GET'])
def get_note(note_path):
    auth = request.headers.get("Authorization", str())
    if not auth.strip().startswith("Bearer "):
        return return_data(401, "Authorization not provided.")
    token = auth.split(" ", 1)[1]
    is_valid, user = token_to_user(token)
    if not is_valid:
        return return_data(403, user)

    note_id = note_path.rsplit("/", 1)[-1]
    note_abspath = os.path.join(PATH, "notes", str(user.id), note_path)

    id_list_path = os.path.join(PATH, "notes", str(user.id), "_id_list")
    with open(id_list_path) as f:
        id_list = f.read().split(",")

    if note_id not in id_list or not os.path.exists(note_abspath):
        return return_data(404, "Note doesn't exist.")
    if False in [check_b64(path) and path in id_list
                 for path in note_path.split("/")]:
        return return_data(400, "Path is invalid.")
    if note_id[0] == "D":
        return return_data(400, "Directory cannot be retrieved with this "
                                "endpoint, please use /note/list instead.")
    elif note_id[0] == "N":
        with open(note_abspath) as f:
            return return_data(200, data=json.load(f))
    elif note_id[0] == "F":
        with open(note_abspath) as f:
            data = json.load(f)
        data.pop("preview")

        response = make_response(
            send_file(
                io.BytesIO(b64decode(data.pop("content"))),
                data.pop("mimetype")
            )
        )
        response.headers.update(
            ((f"X-note-{key}", value) for key, value in data.items())
        )
        return response, 200


@bp.route("/<string:id>", methods=['PUT'])
def edit_note(id):
    auth = request.headers.get("Authorization", str())
    if not auth.strip().startswith("Bearer "):
        return return_data(401, "Authorization not provided.")
    token = auth.split(" ", 1)[1]
    is_valid, user = token_to_user(token)
    if not is_valid:
        return return_data(403, user)

    if id not in [note.id for note in user.notes]:
        return return_data(404, "Note with given id doesn't exist.")

    title = request.form.get("title", "")
    body = request.form.get("body", "")
    uploaded_version = request.form.get("version", "")

    if not title:
        return return_data(400, "Title not provided.")
    if len(title) >= 50:
        return return_data(400, "Title is too long.")
    if not uploaded_version:
        return return_data(400, "version not provided.")

    body_strip = re.sub("\\s", " ", body)

    preview = body_strip if len(body_strip) <= 50 \
        else body_strip[:47] + "..."

    note = Note.query.filter_by(user_id=user.id, id=id).first()

    version = secrets.token_hex(4)
    while uploaded_version == version or note.version == version:
        version = secrets.token_hex(4)

    if uploaded_version == note.version:
        with open(os.path.join(PATH, "notes", str(user.id), id), "w") as f:
            f.write(body)
    else:
        with open(os.path.join(PATH, "notes", str(user.id), id), "a") as f:
            f.write("\n--------On this computer--------\n")
            f.write(body)

    note.title = title
    note.preview = preview
    note.version = version
    note.edited_time = time.time()

    db.session.commit()

    return return_data(201, "Successfully uploaded!")
