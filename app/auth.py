"""
User accounts and session-based authentication.
Real signup/login (not a single shared password) — matches the PS's own
distinction between "administrators" and "analysts" as separate users.

Passwords are hashed with werkzeug's generate_password_hash (bundled
with Flask, industry-standard PBKDF2-based hashing) — never stored in
plain text. Sessions are Flask's built-in signed-cookie sessions.
"""

import re
from functools import wraps
from flask import session, redirect, url_for, request
from werkzeug.security import generate_password_hash, check_password_hash

from case_db import create_user, get_user_by_username

PASSWORD_MIN_LENGTH = 8


def validate_password(password):
    """
    Enforce password requirements: at least 8 characters, at least one
    letter, at least one digit. Returns (is_valid, error_message).
    """
    if len(password) < PASSWORD_MIN_LENGTH:
        return False, f"Password must be at least {PASSWORD_MIN_LENGTH} characters long."
    if not re.search(r"[A-Za-z]", password):
        return False, "Password must include at least one letter."
    if not re.search(r"\d", password):
        return False, "Password must include at least one number."
    return True, None


def register_user(username, password, confirm_password):
    """
    Create a new account. Returns (success, error_message).
    error_message is None on success.
    """
    username = username.strip()

    if not username or len(username) < 3:
        return False, "Username must be at least 3 characters."

    if password != confirm_password:
        return False, "Passwords do not match."

    is_valid, error = validate_password(password)
    if not is_valid:
        return False, error

    password_hash = generate_password_hash(password)
    created = create_user(username, password_hash)

    if not created:
        return False, "That username is already taken."

    return True, None


def authenticate_user(username, password):
    """Check credentials against the stored hash. Returns True/False."""
    user = get_user_by_username(username.strip())
    if not user:
        return False
    return check_password_hash(user["password_hash"], password)


def login_required(view_function):
    """Decorator: redirects to /login if there's no active session."""
    @wraps(view_function)
    def wrapped(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login", next=request.path))
        return view_function(*args, **kwargs)
    return wrapped