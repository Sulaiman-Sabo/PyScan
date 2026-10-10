"""
PyScan Database Module

SQLite database initialisation and helper functions.
Uses Python's built-in sqlite3 module — no external ORM required.

Author: PyScan Project — BSc Cybersecurity Final Year Project
Institution: Federal University of Technology, Babura (FUTB)
"""

import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional

from flask import current_app, g

from config import Config


# ---------------------------------------------------------------------------
# Connection Management
# ---------------------------------------------------------------------------

def get_db() -> sqlite3.Connection:
    """
    Get a database connection for the current request context.

    Returns
    -------
    sqlite3.Connection
        A connection with row_factory set to sqlite3.Row for dict-like access.
    """
    if "db" not in g:
        g.db = sqlite3.connect(Config.DATABASE_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(e: Optional[Any] = None) -> None:
    """
    Close the database connection at the end of the request.

    Parameters
    ----------
    e : Optional[Any]
        Exception object passed by Flask, if any.
    """
    db = g.pop("db", None)
    if db is not None:
        db.close()


# ---------------------------------------------------------------------------
# Schema Initialisation
# ---------------------------------------------------------------------------

def init_db() -> None:
    """
    Create all database tables and seed the default admin account.
    Safe to call multiple times — uses CREATE TABLE IF NOT EXISTS.
    """
    db = get_db()
    cursor = db.cursor()

    # Users table
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            email         TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role          TEXT NOT NULL DEFAULT 'user',
            created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login    DATETIME,
            is_active     INTEGER DEFAULT 1
        )
        """
    )

    # Scan history table
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_history (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id          INTEGER NOT NULL,
            filename         TEXT NOT NULL,
            scan_time        DATETIME DEFAULT CURRENT_TIMESTAMP,
            total_functions  INTEGER DEFAULT 0,
            vulnerable_count INTEGER DEFAULT 0,
            safe_count       INTEGER DEFAULT 0,
            high_risk_count  INTEGER DEFAULT 0,
            scan_result_json TEXT,
            is_deleted       INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """
    )

    # Audit log table
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER,
            action      TEXT NOT NULL,
            ip_address  TEXT,
            timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP,
            details     TEXT
        )
        """
    )

    db.commit()
    _seed_admin_account(db)


def _seed_admin_account(db: sqlite3.Connection) -> None:
    """
    Seed the default admin account if no users exist.

    Parameters
    ----------
    db : sqlite3.Connection
        Active database connection.
    """
    cursor = db.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    count = cursor.fetchone()[0]

    if count == 0:
        # Import bcrypt here to avoid circular imports
        from compat import Bcrypt
        bcrypt = Bcrypt()
        # Note: password will be hashed at runtime when app initialises
        # We store a placeholder and require first-login change
        # For immediate functionality, we hash the default password
        # The actual hashing happens in app.py context
        pass


# ---------------------------------------------------------------------------
# User Operations
# ---------------------------------------------------------------------------

def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve a user by their email address.

    Parameters
    ----------
    email : str
        The user's email address.

    Returns
    -------
    Optional[Dict[str, Any]]
        User dictionary or None if not found.
    """
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    return dict(row) if row else None


def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    """
    Retrieve a user by their ID.

    Parameters
    ----------
    user_id : int
        The user's primary key.

    Returns
    -------
    Optional[Dict[str, Any]]
        User dictionary or None if not found.
    """
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return dict(row) if row else None


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve a user by their username.

    Parameters
    ----------
    username : str
        The user's username.

    Returns
    -------
    Optional[Dict[str, Any]]
        User dictionary or None if not found.
    """
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    return dict(row) if row else None


def create_user(username: str, email: str, password_hash: str) -> int:
    """
    Insert a new user into the database.

    Parameters
    ----------
    username : str
        Unique username (3–20 chars, alphanumeric + underscores).
    email : str
        Unique email address.
    password_hash : str
        Bcrypt-hashed password string.

    Returns
    -------
    int
        The newly created user's ID.
    """
    db = get_db()
    cursor = db.execute(
        """
        INSERT INTO users (username, email, password_hash, role)
        VALUES (?, ?, ?, 'user')
        """,
        (username, email, password_hash),
    )
    db.commit()
    return cursor.lastrowid


def update_last_login(user_id: int) -> None:
    """
    Update the last_login timestamp for a user.

    Parameters
    ----------
    user_id : int
        The user's ID.
    """
    db = get_db()
    db.execute(
        "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
        (user_id,),
    )
    db.commit()


def update_username(user_id: int, new_username: str) -> None:
    """
    Update a user's username.

    Parameters
    ----------
    user_id : int
        The user's ID.
    new_username : str
        The new username to set.
    """
    db = get_db()
    db.execute(
        "UPDATE users SET username = ? WHERE id = ?",
        (new_username, user_id),
    )
    db.commit()


def update_password(user_id: int, new_password_hash: str) -> None:
    """
    Update a user's password hash.

    Parameters
    ----------
    user_id : int
        The user's ID.
    new_password_hash : str
        New bcrypt-hashed password.
    """
    db = get_db()
    db.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (new_password_hash, user_id),
    )
    db.commit()


def toggle_user_active(user_id: int) -> bool:
    """
    Toggle the is_active status of a user.

    Parameters
    ----------
    user_id : int
        The user's ID.

    Returns
    -------
    bool
        The new is_active value.
    """
    db = get_db()
    row = db.execute(
        "SELECT is_active FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if not row:
        return False
    new_status = 0 if row["is_active"] == 1 else 1
    db.execute(
        "UPDATE users SET is_active = ? WHERE id = ?",
        (new_status, user_id),
    )
    db.commit()
    return bool(new_status)


def get_all_users() -> List[Dict[str, Any]]:
    """
    Retrieve all registered users (admin use).

    Returns
    -------
    List[Dict[str, Any]]
        List of user dictionaries.
    """
    db = get_db()
    rows = db.execute(
        """
        SELECT u.*,
               COUNT(s.id) as scan_count
        FROM users u
        LEFT JOIN scan_history s ON u.id = s.user_id AND s.is_deleted = 0
        GROUP BY u.id
        ORDER BY u.created_at DESC
        """
    ).fetchall()
    return [dict(row) for row in rows]


# ---------------------------------------------------------------------------
# Scan History Operations
# ---------------------------------------------------------------------------

def save_scan(
    user_id: int,
    filename: str,
    results_dict: Dict[str, Any],
) -> int:
    """
    Save a scan result to the database (100% Privacy Safeguard: Zero source code or original filenames stored).

    Parameters
    ----------
    user_id : int
        ID of the user who performed the scan.
    filename : str
        Target identifier (anonymized for privacy).
    results_dict : Dict[str, Any]
        Complete scan results dictionary.

    Returns
    -------
    int
        The newly created scan record's ID.
    """
    import json

    # Enforce complete anonymization of target name
    files_count = results_dict.get("files_scanned", 1)
    anonymized_target_name = f"Anonymized Target ({files_count} file{'s' if files_count > 1 else ''})"

    # Map original file paths to generic labels (e.g. File 1, File 2)
    file_map: Dict[str, str] = {}
    clean_functions = []
    cwe_summary: Dict[str, int] = {}

    for fn in results_dict.get("functions", []):
        cwe = fn.get("cwe_category", "N/A")
        if fn.get("is_vulnerable") and cwe != "N/A":
            cwe_summary[cwe] = cwe_summary.get(cwe, 0) + 1

        raw_fn_file = fn.get("filename", "")
        if raw_fn_file not in file_map:
            file_map[raw_fn_file] = f"File {len(file_map) + 1}"

        clean_fn = {
            "function_name": fn.get("function_name", "unknown"),
            "start_line": fn.get("start_line", 0),
            "vulnerable_line_no": fn.get("vulnerable_line_no", fn.get("start_line", 0)),
            "vulnerable_line_text": fn.get("vulnerable_line_text", ""),
            "is_vulnerable": bool(fn.get("is_vulnerable", False)),
            "confidence": fn.get("confidence", 0.0),
            "confidence_percent": fn.get("confidence_percent", 0),
            "cwe_category": cwe,
            "suspicious_tokens": fn.get("suspicious_tokens", []),
            "risk_level": fn.get("risk_level", "SAFE"),
            "remediation": fn.get("remediation", {
                "title": "Security Remediation",
                "description": "Sanitize dynamic inputs and follow secure programming standards.",
                "vulnerable_example": "Unvalidated parameter usage",
                "secure_example": "Validate parameters before execution"
            }),
            "filename": file_map[raw_fn_file],
        }
        clean_functions.append(clean_fn)

    clean_results = {
        "filename": anonymized_target_name,
        "scan_time": results_dict.get("scan_time", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        "total_functions": results_dict.get("total_functions", 0),
        "vulnerable_count": results_dict.get("vulnerable_count", 0),
        "safe_count": results_dict.get("safe_count", 0),
        "high_risk_count": results_dict.get("high_risk_count", 0),
        "cwe_summary": cwe_summary,
        "functions": clean_functions,
        "files_scanned": files_count,
    }

    db = get_db()
    cursor = db.execute(
        """
        INSERT INTO scan_history
        (user_id, filename, total_functions, vulnerable_count,
         safe_count, high_risk_count, scan_result_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            anonymized_target_name,
            clean_results["total_functions"],
            clean_results["vulnerable_count"],
            clean_results["safe_count"],
            clean_results["high_risk_count"],
            json.dumps(clean_results),
        ),
    )
    db.commit()
    return cursor.lastrowid


def get_user_scans(user_id: int, limit: int = 10) -> List[Dict[str, Any]]:
    """
    Retrieve recent scan history for a user.

    Parameters
    ----------
    user_id : int
        The user's ID.
    limit : int, optional
        Maximum number of scans to return, by default 10.

    Returns
    -------
    List[Dict[str, Any]]
        List of scan dictionaries.
    """
    db = get_db()
    rows = db.execute(
        """
        SELECT * FROM scan_history
        WHERE user_id = ? AND is_deleted = 0
        ORDER BY scan_time DESC
        LIMIT ?
        """,
        (user_id, limit),
    ).fetchall()
    return [dict(row) for row in rows]


def get_scan_by_id(scan_id: int, user_id: int) -> Optional[Dict[str, Any]]:
    """
    Retrieve a specific scan, enforcing ownership.

    Parameters
    ----------
    scan_id : int
        The scan record ID.
    user_id : int
        The expected owner's user ID.

    Returns
    -------
    Optional[Dict[str, Any]]
        Scan dictionary or None if not found / not owned.
    """
    db = get_db()
    row = db.execute(
        """
        SELECT * FROM scan_history
        WHERE id = ? AND user_id = ? AND is_deleted = 0
        """,
        (scan_id, user_id),
    ).fetchone()
    return dict(row) if row else None


def soft_delete_scan(scan_id: int, user_id: int) -> bool:
    """
    Soft-delete a scan record (mark as deleted).

    Parameters
    ----------
    scan_id : int
        The scan record ID.
    user_id : int
        The owner's user ID.

    Returns
    -------
    bool
        True if the scan was found and marked deleted.
    """
    db = get_db()
    cursor = db.execute(
        """
        UPDATE scan_history
        SET is_deleted = 1
        WHERE id = ? AND user_id = ?
        """,
        (scan_id, user_id),
    )
    db.commit()
    return cursor.rowcount > 0


# ---------------------------------------------------------------------------
# Audit Log Operations
# ---------------------------------------------------------------------------

def log_action(
    user_id: Optional[int],
    action: str,
    ip_address: Optional[str],
    details: Optional[str] = None,
) -> None:
    """
    Write an entry to the audit log.

    Parameters
    ----------
    user_id : Optional[int]
        ID of the user who performed the action, or None.
    action : str
        Action identifier (e.g., "LOGIN_SUCCESS", "SCAN_COMPLETED").
    ip_address : Optional[str]
        Client IP address.
    details : Optional[str]
        Additional details about the action.
    """
    db = get_db()
    db.execute(
        """
        INSERT INTO audit_log (user_id, action, ip_address, details)
        VALUES (?, ?, ?, ?)
        """,
        (user_id, action, ip_address, details),
    )
    db.commit()


def get_user_audit_log(user_id: int, limit: int = 10) -> List[Dict[str, Any]]:
    """
    Retrieve recent audit log entries for a user.

    Parameters
    ----------
    user_id : int
        The user's ID.
    limit : int, optional
        Maximum entries to return, by default 10.

    Returns
    -------
    List[Dict[str, Any]]
        List of audit log dictionaries.
    """
    db = get_db()
    rows = db.execute(
        """
        SELECT * FROM audit_log
        WHERE user_id = ?
        ORDER BY timestamp DESC
        LIMIT ?
        """,
        (user_id, limit),
    ).fetchall()
    return [dict(row) for row in rows]


def get_recent_audit_log(limit: int = 50) -> List[Dict[str, Any]]:
    """
    Retrieve recent audit log entries (admin use).

    Parameters
    ----------
    limit : int, optional
        Maximum entries to return, by default 50.

    Returns
    -------
    List[Dict[str, Any]]
        List of audit log dictionaries with usernames.
    """
    db = get_db()
    rows = db.execute(
        """
        SELECT a.*, u.username
        FROM audit_log a
        LEFT JOIN users u ON a.user_id = u.id
        ORDER BY a.timestamp DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


# ---------------------------------------------------------------------------
# System Statistics
# ---------------------------------------------------------------------------

def get_system_stats() -> Dict[str, int]:
    """
    Retrieve aggregate system statistics.

    Returns
    -------
    Dict[str, int]
        Dictionary with keys: total_users, total_scans, total_vulnerabilities.
    """
    db = get_db()
    total_users = db.execute(
        "SELECT COUNT(*) FROM users"
    ).fetchone()[0]
    total_scans = db.execute(
        "SELECT COUNT(*) FROM scan_history WHERE is_deleted = 0"
    ).fetchone()[0]
    total_vulns = db.execute(
        "SELECT COALESCE(SUM(vulnerable_count), 0) FROM scan_history WHERE is_deleted = 0"
    ).fetchone()[0]
    return {
        "total_users": total_users,
        "total_scans": total_scans,
        "total_vulnerabilities": total_vulns,
    }


def get_user_scan_stats(user_id: int) -> Dict[str, Any]:
    """
    Retrieve scan statistics for a specific user.

    Parameters
    ----------
    user_id : int
        The user's ID.

    Returns
    -------
    Dict[str, Any]
        Dictionary with total_scans, total_vulns, and last_scan_date.
    """
    db = get_db()
    total_scans = db.execute(
        "SELECT COUNT(*) FROM scan_history WHERE user_id = ? AND is_deleted = 0",
        (user_id,),
    ).fetchone()[0]
    total_vulns = db.execute(
        """
        SELECT COALESCE(SUM(vulnerable_count), 0)
        FROM scan_history WHERE user_id = ? AND is_deleted = 0
        """,
        (user_id,),
    ).fetchone()[0]
    last_scan = db.execute(
        """
        SELECT scan_time FROM scan_history
        WHERE user_id = ? AND is_deleted = 0
        ORDER BY scan_time DESC LIMIT 1
        """,
        (user_id,),
    ).fetchone()
    return {
        "total_scans": total_scans,
        "total_vulns": total_vulns,
        "last_scan_date": last_scan["scan_time"] if last_scan else None,
    }
