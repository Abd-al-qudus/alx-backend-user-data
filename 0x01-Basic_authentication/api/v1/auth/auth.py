#!/usr/bin/env python3
"""authentication class"""
from flask import request
from typing import List, TypeVar


class Auth:
    """base class for authentication"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """check whether the path is in the excluded path"""
        if path is None:
            return True
        if excluded_paths is None or len(excluded_paths) == 0:
            return True
        path = (path + "/") if path[-1] != "/" else path
        for paths in excluded_paths:
            if path == paths:
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """check the authorizatiion header"""
        if request is None:
            return None
        header = request.headers.get("Authorization")
        if header is None:
            return None
        return header

    def current_user(self, request=None) -> TypeVar('User'):
        """check the snapshot of the user instance"""
        return None
