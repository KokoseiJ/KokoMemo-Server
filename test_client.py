import base64
import requests


def get_basic_auth(id, pw):
    return f"Basic {base64.b64encode(f'{id}:{pw}'.encode()).decode()}"


class MemoClient:
    def __init__(self, id, pw, url="http://127.0.0.1:5000"):
        self.url = url
        self.id = id
        self.pw = pw

        self.token = None

    def request_register(self, email, nickname):
        r = requests.post(
            f"{self.url}/user/register",
            headers={"Authorization": get_basic_auth(self.id, self.pw)},
            data={"email": email, "nickname": nickname}
        )
        data = r.json()['meta']
        print(data['code'], data['message'])

    def verify_register(self, jwt):
        r = requests.post(
            f"{self.url}/user/verify",
            headers={"Authorization": f"Bearer {jwt}"}
        )
        data = r.json()['meta']
        print(data['code'], data['message'])

    def get_token(self):
        r = requests.get(
            f"{self.url}/user/token",
            headers={"Authorization": get_basic_auth(self.id, self.pw)}
        )
        data = r.json()
        message = data['meta']['message']
        if r.status_code != 201:
            raise RuntimeError(
                f"Server returned {r.status_code}: {data['meta']['message']}")
        print(r.status_code, message)
        return data['data']['token']

    def update_token(self):
        self.token = self.get_token()

    def get_list(self):
        return requests.get(
            f"{self.url}/note",
            headers={"Authorization": f"Bearer {self.token}"}
        ).json()['data']

    def get_note(self, id):
        r = requests.get(
            f"{self.url}/note/{id}",
            headers={"Authorization": f"Bearer {self.token}"}
        )
        data = r.json()
        print(data['meta']['code'], data['meta']['message'])
        return data['data']

    def get_file(self, id):
        r = requests.get(
            f"{self.url}/note/{id}",
            headers={"Authorization": f"Bearer {self.token}"}
        )
        data = r.json()
        print(data['meta']['code'], data['meta']['message'])

        r = requests.get(
            f"{self.url}/note/{id}/file",
            headers={"Authorization": f"Bearer {self.token}"}
        )
        return data, r.content

    def upload_note(self, title, type, content, path=""):
        r = requests.post(
            f"{self.url}/note/{path}",
            headers={"Authorization": f"Bearer {self.token}"},
            data={"title": title, "type": type, "content": content}
        )
        data = r.json()['meta']
        print(data['code'], data['message'])
        return r

    def upload_file(self, title, file, path="", mimetype=None, type="F"):
        r = requests.post(
            f"{self.url}/note/{path}",
            headers={"Authorization": f"Bearer {self.token}"},
            data={"title": title, "type": type, "mimetype": mimetype},
            files={"file": ("filename", file)}
        )
        data = r.json()['meta']
        print(data['code'], data['message'])
        return r

    def edit_note(self, path, version, title=None, content=None):
        r = requests.patch(
            f"{self.url}/note/{path}",
            headers={"Authorization": f"Bearer {self.token}"},
            data={
                "title": title,
                "content": content,
                "version": version
            }
        )
        data = r.json()['meta']
        print(data['code'], data['message'])
        return r

    def edit_file(self, path, version, title, file, mimetype=None):
        r = requests.put(
            f"{self.url}/note/{path}",
            headers={"Authorization": f"Bearer {self.token}"},
            data={
                "title": title,
                "mimetype": mimetype,
                "version": version
            },
            files={"file": ("filename", file)}
        )
        data = r.json()['meta']
        print(data['code'], data['message'])
        return r
