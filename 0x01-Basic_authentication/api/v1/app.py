#!/usr/bin/env python3
"""
Route module for the API
"""
from os import getenv
from api.v1.views import app_views
from flask import Flask, jsonify, abort, request
from flask_cors import (CORS, cross_origin)
import os


app = Flask(__name__)
app.register_blueprint(app_views)
CORS(app, resources={r"/api/v1/*": {"origins": "*"}})
auth = None

auth_type = os.environ.get('AUTH_TYPE')

if auth_type:
    from api.v1.auth.auth import Auth
    auth = Auth()


@app.before_request
def before_request():
    """filter the user request"""
    if auth is None:
        return
    excluded_paths = ['/api/v1/status/', '/api/v1/unauthorized/',
                      '/api/v1/forbidden/']
    if auth.require_auth(request.path, excluded_paths):
        return
    if auth.authorization_header(request) is None:
        abort(401, description="Unauthorized")
    if auth.current_user(request) is None:
        abort(403, description="Forbidden")


@app.errorhandler(404)
def not_found(error) -> str:
    """ Not found handler
    """
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(403)
def forbidden(error) -> str:
    """handle forbidden routes"""
    return jsonify({"error": "Forbidden"}), 401


@app.errorhandler(401)
def forbidden(error) -> str:
    """handle unauthorized routes"""
    return jsonify({"error": "Unauthorized"}), 403


if __name__ == "__main__":
    host = getenv("API_HOST", "0.0.0.0")
    port = getenv("API_PORT", "5000")
    app.run(host=host, port=port)
