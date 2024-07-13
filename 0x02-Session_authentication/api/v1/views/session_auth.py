#!/usr/bin/env python3
"""session authentication views"""
from os import getenv
from flask import request, jsonify, abort
from api.v1.views import app_views
from models.user import User


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def session_login() -> str:
    """session_login"""
    user_email = request.form.get('email')
    user_password = request.form.get('password')
    if not user_email:
        return jsonify({"error": "email missing"}), 400
    if not user_password:
        return jsonify({"error": "password missing"}), 400

    try:
        users = User.search({'email': user_email})
    except Exception:
        return jsonify({'error': "no user found for this email"}), 404
    if not users:
        return jsonify({'error': "no users found for this email"}), 404

    user = users[0]
    if not user.is_valid_password(user_password):
        return jsonify({'error': "wrong password"}), 401
    from api.v1.app import auth
    session_cookie = getenv('SESSION_NAME')
    session_id = auth.create_session(user.id)
    response = jsonify(user.to_json())
    response.set_cookie(session_cookie, session_id)
    return response


@app_views.route(
    'auth_session/logout', methods=['DELETE'], strict_slashes=False)
def session_logout():
    """Logout the session"""
    from api.v1.app import auth
    if auth.destroy_session(request):
        return jsonify({}), 200
    else:
        return False, abort(404)
