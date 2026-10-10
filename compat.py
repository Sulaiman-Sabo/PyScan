"""
PyScan Compatibility Layer

Provides fallback implementations for Flask-Bcrypt and Flask-WTF when external
packages are not installed, using Flask and Werkzeug built-ins.
"""

from typing import Any, Dict, List, Optional
from flask import Flask, request, session

try:
    from markupsafe import Markup
except ImportError:
    class Markup(str):  # type: ignore
        def __html__(self) -> str:
            return self


# ---------------------------------------------------------------------------
# Bcrypt Fallback (wraps werkzeug.security)
# ---------------------------------------------------------------------------

try:
    from flask_bcrypt import Bcrypt as SystemBcrypt
except ImportError:
    SystemBcrypt = None


class Bcrypt:
    """Bcrypt compatibility wrapper using werkzeug.security fallback."""

    def __init__(self, app: Optional[Flask] = None) -> None:
        self.impl = SystemBcrypt(app) if SystemBcrypt else None
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        if self.impl:
            self.impl.init_app(app)

    def generate_password_hash(self, password: str, rounds: Optional[int] = None) -> bytes:
        if self.impl:
            return self.impl.generate_password_hash(password, rounds)
        from werkzeug.security import generate_password_hash
        return generate_password_hash(password).encode("utf-8")

    def check_password_hash(self, pw_hash: Any, password: str) -> bool:
        if isinstance(pw_hash, bytes):
            pw_hash_str = pw_hash.decode("utf-8")
        else:
            pw_hash_str = pw_hash
            
        if pw_hash_str.startswith("scrypt:") or pw_hash_str.startswith("pbkdf2:"):
            from werkzeug.security import check_password_hash
            return check_password_hash(pw_hash_str, password)
            
        if self.impl:
            try:
                return self.impl.check_password_hash(pw_hash, password)
            except ValueError:
                return False
                
        from werkzeug.security import check_password_hash
        if pw_hash_str.startswith("$2b$") or pw_hash_str.startswith("$2a$"):
            try:
                import bcrypt
                return bcrypt.checkpw(password.encode("utf-8"), pw_hash_str.encode("utf-8"))
            except Exception:
                return False
        return check_password_hash(pw_hash_str, password)


# ---------------------------------------------------------------------------
# CSRF Protection Fallback
# ---------------------------------------------------------------------------

try:
    from flask_wtf import CSRFProtect as SystemCSRFProtect
except ImportError:
    SystemCSRFProtect = None


class CSRFProtect:
    """CSRFProtect compatibility wrapper."""

    def __init__(self, app: Optional[Flask] = None) -> None:
        self.impl = SystemCSRFProtect(app) if SystemCSRFProtect else None
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        if self.impl:
            self.impl.init_app(app)
        else:
            app.jinja_env.globals["csrf_token"] = lambda: "dummy_csrf_token"


# ---------------------------------------------------------------------------
# WTForms / FlaskForm Fallbacks
# ---------------------------------------------------------------------------

try:
    from flask_wtf import FlaskForm
    from wtforms import EmailField, PasswordField, StringField, SubmitField
    from wtforms.validators import DataRequired, Email, EqualTo, Length, Regexp
    HAS_WTFORMS = True
except ImportError:
    HAS_WTFORMS = False


if not HAS_WTFORMS:
    class DummyField:
        def __init__(self, label: str = "", validators: Optional[List[Any]] = None):
            self.label = label
            self.validators = validators or []
            self.data = ""
            self.errors: List[str] = []
            self.name = ""
            self.id = ""

        def __call__(self, **kwargs: Any) -> Any:
            name = kwargs.get("name", getattr(self, "name", ""))
            field_id = kwargs.get("id", getattr(self, "id", name))
            input_type = kwargs.get("type")
            if not input_type:
                if "password" in name.lower():
                    input_type = "password"
                elif "email" in name.lower():
                    input_type = "email"
                else:
                    input_type = "text"
            val = kwargs.get("value", self.data or "")
            class_attr = kwargs.get("class", kwargs.get("class_", ""))
            placeholder = kwargs.get("placeholder", "")
            raw_html = f'<input type="{input_type}" id="{field_id}" name="{name}" value="{val}" class="{class_attr}" placeholder="{placeholder}">'
            return Markup(raw_html)

    class StringField(DummyField):
        pass

    class PasswordField(DummyField):
        pass

    class EmailField(DummyField):
        pass

    class SubmitField(DummyField):
        pass

    class DataRequired:
        def __init__(self, message: Optional[str] = None):
            self.message = message

    class Email:
        def __init__(self, message: Optional[str] = None):
            self.message = message

    class EqualTo:
        def __init__(self, fieldname: str, message: Optional[str] = None):
            self.fieldname = fieldname
            self.message = message

    class Length:
        def __init__(self, min: int = -1, max: int = -1, message: Optional[str] = None):
            self.min = min
            self.max = max
            self.message = message

    class Regexp:
        def __init__(self, regex: str, flags: int = 0, message: Optional[str] = None):
            self.regex = regex
            self.message = message

    class FlaskForm:
        def __init__(self, formdata: Optional[Any] = None, **kwargs: Any):
            self.errors: Dict[str, List[str]] = {}
            for cls in reversed(self.__class__.__mro__):
                for key, value in cls.__dict__.items():
                    if isinstance(value, DummyField):
                        field_obj = DummyField(value.label, value.validators)
                        field_obj.name = key
                        field_obj.id = key
                        field_obj.data = request.form.get(key, kwargs.get(key, ""))
                        setattr(self, key, field_obj)

        def hidden_tag(self) -> Any:
            return Markup('<input type="hidden" name="csrf_token" value="dummy_csrf_token">')

        def validate_on_submit(self) -> bool:
            if request.method != "POST":
                return False
            return self.validate()

        def validate(self) -> bool:
            valid = True
            for key in dir(self):
                attr = getattr(self, key)
                if isinstance(attr, DummyField):
                    attr.errors = []
                    val = attr.data or ""
                    for v in attr.validators:
                        if isinstance(v, DataRequired) and not val.strip():
                            attr.errors.append(v.message or f"{key} is required.")
                            valid = False
            return valid
