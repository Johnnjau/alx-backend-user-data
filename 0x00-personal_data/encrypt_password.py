#!/usr/bin/env python3
"""encrypt_password
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """
    Args:
        password (str)

    Returns:
        bytes
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Args:
        hashed_password (bytes)
        password (str)

    Returns:
        bool
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
