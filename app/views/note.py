# -*- coding: utf-8 -*-

from flask import Blueprint
from flask import request, send_file, make_response

import io
import os
import re
import json
import secrets

from app.module.b64 import check_b64, b64encode, b64decode
from app.module.util import return_data, token_to_user

from config import PATH


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
            filelist.append(
                get_noteobj(file.name, title, "D", content=get_list(file.path))
            )
    return filelist


def get_preview(content):
    body_strip = re.sub("\\s", " ", content)
    return body_strip if len(body_strip) <= 50 \
        else body_strip[:47] + "..."


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

    note_abspath = os.path.join(PATH, "notes", str(user.id), note_path)

    title = data.get("title")
    _type = data.get("type")
    content = data.get("content")
    mimetype = data.get("mimetype")
    file = request.files.get("file")

    id_list_path = os.path.join(PATH, "notes", str(user.id), "_id_list")
    with open(id_list_path) as f:
        id_list = f.read().split(",")

    if not os.path.exists(note_abspath):
        return return_data(404, "Folder doesn't exist.")
    if False in [check_b64(path) and path in id_list
                 for path in note_path.split("/")]:
        return return_data(400, "Path is invalid.")

    if title is None:
        return return_data(400, "Title not provided.")
    if len(title) >= 50:
        return return_data(400, "Title is too long.")
    if not isinstance(title, str):
        return return_data(400, "Title is not string.")
    if _type not in ["N", "F", "D"]:
        return return_data(400, "Wrong type specified.")
    if _type == "N" and content is None:
        return return_data(400, "Content not provided.")
    if _type == "F":
        if file is None:
            return return_data(400, "File content not provided.")
        if mimetype is not None and not isinstance(mimetype, str):
            return return_data(400, "Mimetype is not a string.")

    while True:
        _id = _type + secrets.token_urlsafe(8)
        if _id not in id_list:
            break

    if _type == "D":
        try:
            fpath = os.path.join(note_abspath, _id)
            os.mkdir(fpath)
        except (FileExistsError, PermissionError):
            return return_data(500, "Failed to create a folder.\n"
                                    "This is server-side error and "
                                    "should not happen at all.\n"
                                    "Please contact administrator for help.")
        with open(os.path.join(fpath, "_title"), "w") as f:
            f.write(title)

        data = get_noteobj(_id, title, "D")
    else:
        version = secrets.token_hex(4)
        if _type == "N":
            mimetype = None
            preview = get_preview(content)

        elif _type == "F":
            if mimetype is None:
                mimetype = "application/octet-stream"
            preview = None
            f = io.BytesIO()
            file.save(f)
            content = b64encode(f.getvalue()).decode()

        data = get_noteobj(
            _id, title, _type, mimetype, preview, content, version)
        with open(os.path.join(note_abspath, _id), "w") as f:
            f.write(json.dumps(data))

        data['content'] = None

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


@bp.route('/<path:note_path>', methods=['PUT'])
def edit_note(note_path):
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

    note_id = note_path.rsplit("/", 1)[-1]
    note_abspath = os.path.join(PATH, "notes", str(user.id), note_path)

    title = data.get("title")
    content = data.get("content")
    version = data.get("version")
    mimetype = data.get("mimetype")
    file = request.files.get("file")

    id_list_path = os.path.join(PATH, "notes", str(user.id), "_id_list")
    with open(id_list_path) as f:
        id_list = f.read().split(",")

    if note_id not in id_list or not os.path.exists(note_abspath):
        return return_data(404, "Note doesn't exist.")
    if False in [check_b64(path) and path in id_list
                 for path in note_path.split("/")]:
        return return_data(400, "Path is invalid.")

    if title is not None:
        if len(title) >= 50:
            return return_data(400, "Title is too long.")
        if not isinstance(title, str):
            return return_data(400, "Title is not a string.")
    if note_id[0] in ["F", "N"]:
        if version is None:
            return return_data(400, "Version not provided.")
        elif not isinstance(version, str):
            return return_data(400, "Version is not a string.")
        if len(version) != 8:
            return return_data(400, "Version has a wrong format.")
    if note_id[0] == "F" and mimetype is not None and\
            not isinstance(mimetype, str):
        return return_data(400, "Mimetype is not a string.")

    if note_id[0] == "D":
        with open(os.path.join(note_abspath, "_title")) as f:
            orig_title = f.read()
        if title is not None and orig_title != title:
            with open(os.path.join(note_abspath, "_title"), "w") as f:
                f.write(title)
            return_str = "Edited successfully!"
        else:
            return_str = "Not modified."
        data = get_noteobj(note_id, title if title else orig_title, "D")
    else:
        new_version = secrets.token_hex(4)
        modified = False
        with open(note_abspath) as f:
            data = json.load(f)
        if title is not None and data['title'] != title:
            data['title'] = title
            modified = True
        if note_id[0] == "N" and content is not None\
                and content != data['content']:
            if data['version'] == version:
                data['content'] = content
            else:
                data['content'] = content + \
                    f"\n\n-----Old version({data['version']})-----" + \
                    data['content']
            data['preview'] = get_preview(data['content'])
            modified = True
        elif note_id[0] == "F":
            if file is not None:
                f = io.BytesIO()
                file.save(f)
                content = b64encode(f.getvalue()).decode()
                if content != data['content']:
                    data['content'] = content
                    modified = True
            if mimetype is not None and data['mimetype'] != mimetype:
                data['mimetype'] = mimetype
                modified = True
        if modified:
            data['version'] = new_version
            with open(note_abspath, "w") as f:
                json.dump(data, f)
            return_str = "Edited successfully!"
        else:
            return_str = "Not modified."

    return return_data(200, return_str, data)
