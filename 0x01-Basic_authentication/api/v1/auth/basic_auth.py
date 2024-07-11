#!/usr/bin/env python3
"""BaseicAuth class module"""
from .auth import Auth
import base64
from typing import TypeVar
from models.user import User


class BasicAuth(Auth):
    """BasicAuth class inherits from Auth class"""
    def __init__(self) -> None:
        """contructor method"""
        pass

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """extract_base64_authorization_header method"""

        if not authorization_header or \
                not isinstance(authorization_header, str):
            return None

        if authorization_header[:6] != 'Basic ':
            return None

        return authorization_header[6:]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """def decode_base64_authorization_header method"""
        if not base64_authorization_header or \
                not isinstance(base64_authorization_header, str):
            return None

        try:
            decoded = base64.b64decode(base64_authorization_header)
            decoded_str = decoded.decode('utf-8')
            return decoded_str

        except (base64.binascii.Error, UnicodeDecodeError):
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> (str, str):
        """extract_user_credentials method"""
        if not decoded_base64_authorization_header:
            return (None, None)

        if not isinstance(decoded_base64_authorization_header, str):
            return (None, None)

        if ':' not in decoded_base64_authorization_header:
            return (None, None)

        email, password = decoded_base64_authorization_header.split(':')
        return(email, password)

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """def user_object_from_credentials method"""
        if not user_email or not isinstance(user_email, str):
            return None

        if not user_pwd or not isinstance(user_pwd, str):
            return None

        user = User()
        valid_user = user.search({"email": user_email})

        if valid_user:
            if valid_user[0].is_valid_password(user_pwd):
                return valid_user[0]
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """current_user method"""

        authorization_header = self.authorization_header(request)

        base64_authorization_header = self.extract_base64_authorization_header(
            authorization_header)

        decoded = self.decode_base64_authorization_header(
            base64_authorization_header)

        user_credentials = self.extract_user_credentials(decoded)

        email = user_credentials[0]

        pwd = user_credentials[1]

        return self.user_object_from_credentials(email, pwd)
