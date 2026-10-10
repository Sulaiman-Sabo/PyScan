"""
PyScan Dashboard Blueprint

Handles user dashboard, profile management, scan history, and admin panel.
All routes require authentication.

Author: PyScan Project — BSc Cybersecurity Final Year Project
Institution: Federal University of Technology, Babura (FUTB)
"""

import json
from typing import Any, Dict, Optional

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
    EqualTo,
    FlaskForm,
    Length,
    PasswordField,
    Regexp,
    StringField,
    SubmitField,
)

from auth import admin_required, login_required, validate_password_strength
from database import (
    get_all_users,
    get_db,
    get_recent_audit_log,
    get_scan_by_id,
    get_system_stats,
    get_user_audit_log,
    get_user_by_id,
    get_user_by_username,
    get_user_scan_stats,
    get_user_scans,
    log_action,
    soft_delete_scan,
    toggle_user_active,
    update_password,
    update_username,
)

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/dashboard")
bcrypt = Bcrypt()


# ---------------------------------------------------------------------------
# Forms
# ---------------------------------------------------------------------------

class ProfileForm(FlaskForm):
    """Form for updating user profile."""
    username = StringField(
        "Username",
        validators=[
            DataRequired(),
            Length(min=3, max=20),
            Regexp(r"^[A-Za-z0-9_]+$", message="Only letters, numbers, and underscores."),
        ],
    )
    submit = SubmitField("Update Profile")


class ChangePasswordForm(FlaskForm):
    """Form for changing password."""
    current_password = PasswordField("Current Password", validators=[DataRequired()])
    new_password = PasswordField("New Password", validators=[DataRequired()])
    confirm_new_password = PasswordField(
        "Confirm New Password",
        validators=[DataRequired(), EqualTo("new_password")],
    )
    submit = SubmitField("Change Password")


# ---------------------------------------------------------------------------
# User Dashboard Routes
# ---------------------------------------------------------------------------

@dashboard_bp.route("/")
@login_required
def index() -> Any:
    """
    Render the user dashboard with scan history and statistics.

    Returns
    -------
    Any
        Rendered dashboard.html template.
    """
    user_id = session["user_id"]
    user = get_user_by_id(user_id)
    recent_scans = get_user_scans(user_id, limit=10)
    stats = get_user_scan_stats(user_id)

    # Parse scan_result_json for the trend chart
    scan_trends = []
    for scan in recent_scans[:5][::-1]:  # Last 5, oldest first
        scan_trends.append({
            "filename": scan["filename"][:20] + "..." if len(scan["filename"]) > 20 else scan["filename"],
            "vulnerable_count": scan["vulnerable_count"],
            "total_functions": max(scan["total_functions"], 1),
        })

    return render_template(
        "dashboard/dashboard.html",
        recent_scans=recent_scans,
        total_scans=stats["total_scans"],
        total_vulns_found=stats["total_vulns"],
        username=session["username"],
        last_login=user["last_login"] if user else None,
        scan_trends=scan_trends,
    )


@dashboard_bp.route("/scan/<int:scan_id>")
@login_required
def view_scan(scan_id: int) -> Any:
    """
    View a specific historical scan result.

    Parameters
    ----------
    scan_id : int
        The scan record ID.

    Returns
    -------
    Any
        Rendered results.html with historical data, or redirect on error.
    """
    user_id = session["user_id"]
    scan = get_scan_by_id(scan_id, user_id)

    if scan is None:
        flash("Scan not found or you do not have permission to view it.", "danger")
        return redirect(url_for("dashboard.index"))

    scan_results = json.loads(scan["scan_result_json"])
    summary_color = "danger" if scan_results["vulnerable_count"] > 0 else "success"

    return render_template(
        "results.html",
        scan_results=scan_results,
        summary_color=summary_color,
        from_dashboard=True,
    )


@dashboard_bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile() -> Any:
    """
    Render and handle the user profile page.

    GET: Display profile information.
    POST: Update username if valid.

    Returns
    -------
    Any
        Rendered profile.html template.
    """
    user_id = session["user_id"]
    user = get_user_by_id(user_id)
    profile_form = ProfileForm()
    password_form = ChangePasswordForm()
    audit_log = get_user_audit_log(user_id, limit=10)
    stats = get_user_scan_stats(user_id)

    if profile_form.validate_on_submit():
        new_username = profile_form.username.data.strip()

        # Check if username is already taken by another user
        existing = get_user_by_username(new_username)
        if existing is not None and existing["id"] != user_id:
            flash("Username already taken. Please choose another.", "danger")
        else:
            update_username(user_id, new_username)
            session["username"] = new_username
            log_action(user_id, "PROFILE_UPDATED", request.remote_addr, f"New username: {new_username}")
            flash("Profile updated successfully.", "success")
            return redirect(url_for("dashboard.profile"))

    # Pre-populate username field
    if request.method == "GET":
        profile_form.username.data = user["username"]

    return render_template(
        "dashboard/profile.html",
        user=user,
        profile_form=profile_form,
        password_form=password_form,
        audit_log=audit_log,
        stats=stats,
    )


@dashboard_bp.route("/change-password", methods=["POST"])
@login_required
def change_password() -> Any:
    """
    Handle password change requests.

    Verifies current password, validates new password strength, updates hash,
    and forces re-login.

    Returns
    -------
    Any
        Redirect to login on success, or profile on failure.
    """
    user_id = session["user_id"]
    user = get_user_by_id(user_id)
    password_form = ChangePasswordForm()

    if password_form.validate_on_submit():
        current_password = password_form.current_password.data
        new_password = password_form.new_password.data

        # Verify current password
        if not bcrypt.check_password_hash(user["password_hash"], current_password):
            flash("Current password is incorrect.", "danger")
            return redirect(url_for("dashboard.profile"))

        # Ensure new password is different
        if bcrypt.check_password_hash(user["password_hash"], new_password):
            flash("New password must be different from your current password.", "danger")
            return redirect(url_for("dashboard.profile"))

        # Validate new password strength
        valid, msg = validate_password_strength(new_password)
        if not valid:
            flash(msg, "danger")
            return redirect(url_for("dashboard.profile"))

        # Update password
        new_hash = bcrypt.generate_password_hash(new_password).decode("utf-8")
        update_password(user_id, new_hash)

        log_action(user_id, "PASSWORD_CHANGED", request.remote_addr, None)
        session.clear()
        flash("Password updated. Please log in with your new password.", "success")
        return redirect(url_for("auth.login"))

    # If form validation failed, show errors
    for field, errors in password_form.errors.items():
        for error in errors:
            flash(f"{field}: {error}", "danger")
    return redirect(url_for("dashboard.profile"))


@dashboard_bp.route("/delete-scan/<int:scan_id>", methods=["POST"])
@login_required
def delete_scan(scan_id: int) -> Any:
    """
    Soft-delete a scan record.

    Parameters
    ----------
    scan_id : int
        The scan record ID to delete.

    Returns
    -------
    Any
        Redirect to dashboard.
    """
    user_id = session["user_id"]
    success = soft_delete_scan(scan_id, user_id)

    if success:
        log_action(user_id, "SCAN_DELETED", request.remote_addr, f"Scan ID: {scan_id}")
        flash("Scan deleted successfully.", "success")
    else:
        flash("Scan not found or you do not have permission to delete it.", "danger")

    return redirect(url_for("dashboard.index"))


# ---------------------------------------------------------------------------
# Admin Routes
# ---------------------------------------------------------------------------

@dashboard_bp.route("/admin")
@login_required
@admin_required
def admin_panel() -> Any:
    """
    Render the admin panel with system statistics and user management.

    Returns
    -------
    Any
        Rendered admin panel template.
    """
    system_stats = get_system_stats()
    users = get_all_users()
    audit_log = get_recent_audit_log(limit=50)

    return render_template(
        "dashboard/admin.html",
        system_stats=system_stats,
        users=users,
        audit_log=audit_log,
    )


@dashboard_bp.route("/admin/toggle-user/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def toggle_user(user_id: int) -> Any:
    """
    Toggle a user's active status.

    Parameters
    ----------
    user_id : int
        The user ID to toggle.

    Returns
    -------
    Any
        Redirect to admin panel.
    """
    admin_id = session["user_id"]

    # Prevent self-deactivation
    if user_id == admin_id:
        flash("You cannot deactivate your own account.", "danger")
        return redirect(url_for("dashboard.admin_panel"))

    new_status = toggle_user_active(user_id)
    status_text = "activated" if new_status else "deactivated"
    log_action(admin_id, "ADMIN_USER_TOGGLE", request.remote_addr, f"User ID {user_id} {status_text}")
    flash(f"User has been {status_text}.", "success")
    return redirect(url_for("dashboard.admin_panel"))


@dashboard_bp.route("/settings", methods=["GET", "POST"])
@login_required
def settings() -> Any:
    """Render and handle user scanner and privacy settings."""
    user_id = session["user_id"]
    user = get_user_by_id(user_id)

    if request.method == "POST":
        thresh = request.form.get("threshold", "0.65")
        fmt = request.form.get("report_format", "sarif")
        session["user_threshold"] = float(thresh)
        session["user_report_format"] = fmt
        flash("Settings updated successfully.", "success")
        return redirect(url_for("dashboard.settings"))

    return render_template(
        "dashboard/settings.html",
        user=user,
        current_threshold=session.get("user_threshold", 0.65),
        current_report_format=session.get("user_report_format", "sarif"),
    )
