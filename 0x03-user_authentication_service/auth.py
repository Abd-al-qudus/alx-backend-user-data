#!/usr/bin/env python3
"""this module contains the authentication methods
    for the authentication services API"""
import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
import bcrypt


def _hash_password(password: str) -> bytes:
    """returns bytes from hashed password"""
    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    return hashed_pw


class Auth:
    """a class to handle the Authentication states"""
    
    def __init__(self) -> None:
        self._db = DB()

    def register_user(self, email, password) -> User:
        """register the user in the database"""
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            hashed_pw = _hash_password(password)
            self._db.update_user(user.id, hashed_password=hashed_pw)
            return user
        finally:
            raise ValueError('User {} already exists.'.format(email))

    def valid_login(self, email, password) -> bool:
        """check whether user has a valid login credentials"""
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False
        hashed_pw = _hash_password(password)
        return bcrypt.checkpw(hashed_pw, user.hashed_password)
