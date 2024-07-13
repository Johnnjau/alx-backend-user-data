#!/usr/bin/env python3
""" authentication class"""

from flask import request
from typing import List, TypeVar


class Auth():
    """ authentication"""
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ return False - path"""
        if path is None or not excluded_paths:
            return True
        for i in excluded_paths:
            if i.endswith('*') and path.startswith(i[:-1]):
                return False
            elif i in {path, path + '/'}:
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """ checks for authorization in request header"""
        if request is None or "Authorization" not in request.headers:
            return None
        else:
            return request.headers.get("Authorization")

    def current_user(self, request=None) -> TypeVar('User'):
        """ current_user placeholder"""
        return None
