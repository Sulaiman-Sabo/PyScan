"""
PyScan Authentication Blueprint

Handles user registration, login, logout, password reset, and session management.
Implements bcrypt password hashing, CSRF protection, rate limiting, and secure
session handling.

Author: PyScan Project — BSc Cybersecurity Final Year Project
Institution: Federal University of Technology, Babura (FUTB)
"""

import re
import secrets
from datetime import datetime, timedelta
from functools import wraps
from typing import Any, Dict, List, Optional, Tuple

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from compat import (
    Bcrypt,
    DataRequired,
    Email,
    EmailField,
    EqualTo,
    FlaskForm,
    Length,
    PasswordField,
    Regexp,
    StringField,
    SubmitField,
)

from database import (
    create_user,
    get_db,
    get_user_by_email,
    get_user_by_id,
    get_user_by_username,
    log_action,
    update_last_login,
)

# ---------------------------------------------------------------------------
# Blueprint Setup
# ---------------------------------------------------------------------------

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")
bcrypt = Bcrypt()

# In-memory rate limit store: {ip_address: [(timestamp, count), ...]}
_rate_limit_store: Dict[str, List[datetime]] = {}


# ---------------------------------------------------------------------------
# Forms (Flask-WTF with CSRF)
# ---------------------------------------------------------------------------

class LoginForm(FlaskForm):
    """Login form with CSRF protection."""
    email = EmailField("Email", validators=[DataRequired(), Regexp(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", message="Invalid email address.")])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Log In")


class RegisterForm(FlaskForm):
    """Registration form with CSRF protection and validation."""
    username = StringField(
        "Username",
        validators=[
            DataRequired(),
            Length(min=3, max=20, message="Username must be 3–20 characters."),
            Regexp(
                r"^[A-Za-z0-9_]+$",
                message="Username may only contain letters, numbers, and underscores.",
            ),
        ],
    )
    email = EmailField("Email", validators=[DataRequired(), Regexp(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", message="Invalid email address.")])
    password = PasswordField(
        "Password",
        validators=[DataRequired()],
    )
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[
            DataRequired(),
            EqualTo("password", message="Passwords must match."),
        ],
    )
    submit = SubmitField("Create Account")


class ForgotPasswordForm(FlaskForm):
    """Password reset request form."""
    email = EmailField("Email", validators=[DataRequired(), Regexp(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", message="Invalid email address.")])
    submit = SubmitField("Send Reset Link")


# ---------------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------------

def login_required(f):
    """
    Decorator that requires the user to be logged in.

    Redirects to the login page with a flash message if the user is not
    authenticated.
    """
    @wraps(f)
    def decorated_function(*args: Any, **kwargs: Any) -> Any:
        if "user_id" not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """
    Decorator that requires the user to be an admin.

    Must be used in combination with @login_required.
    """
    @wraps(f)
    def decorated_function(*args: Any, **kwargs: Any) -> Any:
        if session.get("role") != "admin":
            flash("You do not have permission to access this page.", "danger")
            return redirect(url_for("dashboard.index"))
        return f(*args, **kwargs)
    return decorated_function


# ---------------------------------------------------------------------------
# Rate Limiting
# ---------------------------------------------------------------------------

def _get_client_ip() -> str:
    """
    Get the client's IP address from the request.

    Returns
    -------
    str
        Client IP address.
    """
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"


def check_rate_limit(ip: str) -> Tuple[bool, int]:
    """
    Check if the given IP has exceeded the login attempt rate limit.

    Parameters
    ----------
    ip : str
        Client IP address.

    Returns
    -------
    Tuple[bool, int]
        (allowed: bool, remaining_attempts: int)
    """
    now = datetime.now()
    window = timedelta(seconds=900)  # 15 minutes
    max_attempts = 5

    if ip not in _rate_limit_store:
        _rate_limit_store[ip] = []

    # Remove entries outside the window
    _rate_limit_store[ip] = [
        ts for ts in _rate_limit_store[ip] if now - ts < window
    ]

    attempts = len(_rate_limit_store[ip])
    allowed = attempts < max_attempts
    remaining = max(0, max_attempts - attempts)

    return allowed, remaining


def record_failed_attempt(ip: str) -> None:
    """
    Record a failed login attempt for rate limiting.

    Parameters
    ----------
    ip : str
        Client IP address.
    """
    if ip not in _rate_limit_store:
        _rate_limit_store[ip] = []
    _rate_limit_store[ip].append(datetime.now())


# ---------------------------------------------------------------------------
# Password Validation
# ---------------------------------------------------------------------------

def validate_password_strength(password: str) -> Tuple[bool, str]:
    """
    Validate password strength against security requirements.

    Parameters
    ----------
    password : str
        The password to validate.

    Returns
    -------
    Tuple[bool, str]
        (is_valid: bool, message: str)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit."
    if not re.search(r"""[!@#$%^&*()_+\-=\[\]{};':",.<>?/|`~]""", password):
        return False, "Password must contain at least one special character."
    return True, "Password meets all requirements."


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@auth_bp.route("/login", methods=["GET", "POST"])
def login() -> Any:
    """
    Handle user login.

    GET: Render the login form.
    POST: Validate credentials, create session, and redirect to dashboard.
    """
    if "user_id" in session:
        return redirect(url_for("dashboard.index"))

    form = LoginForm()
    ip = _get_client_ip()

    if form.validate_on_submit():
        # Check rate limit
        allowed, remaining = check_rate_limit(ip)
        if not allowed:
            log_action(None, "LOGIN_BLOCKED", ip, f"IP blocked after 5 failed attempts")
            flash("Too many failed attempts. Please wait 15 minutes.", "danger")
            return render_template("auth/login.html", form=form), 429

        email = form.email.data.strip().lower()
        password = form.password.data

        user = get_user_by_email(email)

        # Same error message for both invalid email and invalid password
        # to prevent email enumeration attacks
        if user is None:
            record_failed_attempt(ip)
            log_action(None, "LOGIN_FAILURE", ip, f"Email not found: {email}")
            flash("Invalid email or password.", "danger")
            return render_template("auth/login.html", form=form)

        if not bcrypt.check_password_hash(user["password_hash"], password):
            record_failed_attempt(ip)
            log_action(user["id"], "LOGIN_FAILURE", ip, "Incorrect password")
            flash("Invalid email or password.", "danger")
            return render_template("auth/login.html", form=form)

        if user["is_active"] == 0:
            log_action(user["id"], "LOGIN_BLOCKED", ip, "Inactive account")
            flash("Your account has been deactivated. Contact admin.", "danger")
            return render_template("auth/login.html", form=form)

        # Regenerate session to prevent fixation
        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["email"] = user["email"]
        session["role"] = user["role"]

        update_last_login(user["id"])
        log_action(user["id"], "LOGIN_SUCCESS", ip, f"User: {user['username']}")
        flash(f"Welcome back, {user['username']}!")
        return redirect(url_for("dashboard.index"))

    return render_template("auth/login.html", form=form)


@auth_bp.route("/register", methods=["GET", "POST"])
def register() -> Any:
    """
    Handle user registration.

    GET: Render the registration form.
    POST: Validate all fields, create user, and redirect to login.
    """
    if "user_id" in session:
        return redirect(url_for("dashboard.index"))

    form = RegisterForm()
    ip = _get_client_ip()

    if form.validate_on_submit():
        username = form.username.data.strip()
        email = form.email.data.strip().lower()
        password = form.password.data

        # Check password strength
        valid, msg = validate_password_strength(password)
        if not valid:
            flash(msg, "danger")
            return render_template("auth/register.html", form=form)

        # Check username uniqueness
        if get_user_by_username(username) is not None:
            flash("Username already taken. Please choose another.", "danger")
            return render_template("auth/register.html", form=form)

        # Check email uniqueness
        if get_user_by_email(email) is not None:
            flash("Email already registered. Please log in instead.", "danger")
            return render_template("auth/register.html", form=form)

        # Hash password and create user
        password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
        user_id = create_user(username, email, password_hash)

        log_action(user_id, "REGISTER_SUCCESS", ip, f"Username: {username}")
        flash("Account created successfully. Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html", form=form)


@auth_bp.route("/logout")
@login_required
def logout() -> Any:
    """
    Log out the current user securely.

    Clears the entire session and redirects to the login page.
    """
    user_id = session.get("user_id")
    ip = _get_client_ip()
    log_action(user_id, "LOGOUT", ip, None)
    session.clear()
    flash("You have been logged out securely.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password() -> Any:
    """
    Handle password reset requests.

    GET: Render the forgot password form.
    POST: Generate a reset token if email exists (displayed on page for demo).
    """
    form = ForgotPasswordForm()
    ip = _get_client_ip()
    reset_token = None

    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        user = get_user_by_email(email)

        # Always show the same message regardless of email existence
        # to prevent email enumeration
        flash("If that email is registered, you will receive a reset link shortly.", "info")

        if user is not None:
            reset_token = secrets.token_urlsafe(32)
            # Store in session with 15-minute expiry for demo purposes
            session["reset_token"] = reset_token
            session["reset_email"] = email
            session["reset_expiry"] = (datetime.now() + timedelta(minutes=15)).isoformat()
            log_action(user["id"], "PASSWORD_RESET_REQUESTED", ip, None)
        else:
            log_action(None, "PASSWORD_RESET_REQUESTED", ip, f"Email not found: {email}")

    return render_template("auth/forgot_password.html", form=form, reset_token=reset_token)
