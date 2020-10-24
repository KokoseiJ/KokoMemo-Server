# -*- coding: utf-8 -*-

def return_data(code: int, message: str = "", data: [list, dict] = None):
    """
    Simple wrapper function for generating a return value that has a format of
    ({'code': code, 'message': message}, code).

    :param code: HTTP Status code
    :param message: Message to be displayed to the user.
    :returns: tuple that has a format of (dict, int) That can be passed to
              flask right away.
    :raises ValueError: If code is not int, It raises ValueError.
    :param data: #TODO: add docstring
    """
    if not isinstance(code, int):
        raise ValueError("code must be integer")

    if data is None:
        return {
            "meta": {
                "code": code,
                "message": message
            }
        }, code
    else:
        return {
            "meta": {
                "code": code,
                "message": message
            },
            "data": data
        }, code
