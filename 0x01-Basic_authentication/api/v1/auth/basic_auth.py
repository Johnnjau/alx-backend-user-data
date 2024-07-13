#!/usr/bin/env python3
""" basic auth class """


from base64 import b64decode
from nntplib import decode_header
from api.v1.auth.auth import Auth
from models.user import User
from typing import TypeVar


class BasicAuth(Auth):
    """ basic auth class """
    def extract_base64_authorization_header(
            self, authorization_header: str) -> str:
        """ extract authorization header"""
        if authorization_header and isinstance(
                authorization_header, str) and authorization_header.startswith(
                    "Basic "):
            return authorization_header[6:]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """Decode authorization header from base64"""
        if base64_authorization_header is None or not isinstance(
                base64_authorization_header, str):
            return None

        try:
            return b64decode(base64_authorization_header).decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> (str, str):
        """Extracts the credentials from the base64 authorization header"""
        if decoded_base64_authorization_header is None or not isinstance(
            decoded_base64_authorization_header,
                str) or ":" not in decoded_base64_authorization_header:
            return (None, None)
        email, password = decoded_base64_authorization_header.split(":", 1)
        return (email, password)

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """Returns the user object from credentials"""
        if user_email is None or not isinstance(
                user_email, str) or user_pwd is None or not isinstance(
                    user_pwd, str):
            return None
        try:
            users = User.search({'email': user_email})
        except Exception:
            return None
        for user in users:
            if user.is_valid_password(user_pwd):
                return user
            return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Returns the current user for the given request and override Auth"""
        auth_header = self.authorization_header(request)
        b64_header = self.extract_base64_authorization_header(auth_header)
        decode_header = self.decode_base64_authorization_header(b64_header)
        user_credentials = self.extract_user_credentials(decode_header)
        return self.user_object_from_credentials(*user_credentials)
