"""
Flask server for the Email Threat Forensics platform.
Routes:
  /signup                 - create a new account
  /login                  - log in
  /logout                 - end the session
  /                       - upload form + analysis results
  /analyze                - POST endpoint that runs the pipeline on an uploaded .eml
  /dashboard              - searchable case management view
  /report/<id>            - downloads a forensic PDF report for a given case
  /audit-log              - chain-of-custody audit trail
  /campaigns              - grouped campaign view
  /run-retention-cleanup  - purges old uploaded files past the retention period

All routes except signup/login require an active session (see auth.py).
Debug mode is OFF by default — only enabled if FLASK_DEBUG=1 is set.
"""

import os
import json
import secrets
from flask import Flask, request, render_template, Response, abort, redirect, url_for, session

from analyze import analyze_email
from case_db import get_all_cases, search_cases, get_case, log_audit_event, get_audit_log
from correlation import get_campaign_groups
from privacy import cleanup_old_uploads, mask_email_address
from auth import login_required, register_user, authenticate_user
from report_generator import generate_pdf_report

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        success, error = register_user(username, password, confirm_password)
        if success:
            session["username"] = username.strip()
            return redirect(url_for("home"))
        return render_template("signup.html", error=error)

    return render_template("signup.html", error=None)


@app.route("/login", methods=["GET", "POST"])
def login():
    next_url = request.args.get("next") or request.form.get("next") or url_for("home")

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        if authenticate_user(username, password):
            session["username"] = username.strip()
            return redirect(next_url)
        return render_template("login.html", error="Invalid username or password.", next_url=next_url)

    return render_template("login.html", error=None, next_url=next_url)


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("login"))


@app.route("/")
@login_required
def home():
    return render_template("index.html", result=None)


@app.route("/analyze", methods=["POST"])
@login_required
def analyze():
    uploaded_file = request.files.get("email_file")

    if not uploaded_file or uploaded_file.filename == "":
        return render_template("index.html", result=None, error="No file selected.")

    save_path = os.path.join(UPLOAD_FOLDER, uploaded_file.filename)
    uploaded_file.save(save_path)

    result = analyze_email(save_path)
    result_json = json.dumps(result, indent=2)

    return render_template("index.html", result=result, result_json=result_json)


@app.route("/dashboard")
@login_required
def dashboard():
    query = request.args.get("q", "").strip()
    mask = request.args.get("mask") == "1"

    if query:
        cases = search_cases(query)
    else:
        cases = get_all_cases()

    if mask:
        for case in cases:
            case["from_address"] = mask_email_address(case.get("from_address", ""))

    return render_template("dashboard.html", cases=cases, query=query, mask=mask)


@app.route("/run-retention-cleanup", methods=["POST"])
@login_required
def run_retention_cleanup():
    retention_days = int(request.form.get("retention_days", 90))
    deleted = cleanup_old_uploads(UPLOAD_FOLDER, retention_days=retention_days)
    log_audit_event(None, "retention_cleanup", f"Deleted {len(deleted)} file(s) older than {retention_days} days: {deleted}")
    return redirect(url_for("dashboard"))


@app.route("/report/<int:case_id>")
@login_required
def report(case_id):
    case = get_case(case_id)
    if not case:
        abort(404, description="Case not found")

    log_audit_event(case_id, "report_downloaded", "PDF forensic report exported")
    pdf_bytes = generate_pdf_report(case)
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=forensic_report_case_{case_id}.pdf"},
    )


@app.route("/audit-log")
@login_required
def audit_log():
    entries = get_audit_log()
    return render_template("audit_log.html", entries=entries)


@app.route("/campaigns")
@login_required
def campaigns():
    groups = get_campaign_groups()
    return render_template("campaigns.html", campaigns=groups)


if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=debug_mode, host="0.0.0.0", port=port)