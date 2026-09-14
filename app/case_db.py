"""
Identity Correlation & Case Management — Case History Database.
Also handles the Chain-of-Custody audit trail and user accounts.

Uses SQLite (built into Python — no extra service to run).
"""

import sqlite3
import os
import json
def _get_db_path():
    if os.environ.get("VERCEL") or not os.access(os.path.dirname(os.path.abspath(__file__)), os.W_OK):
        tmp_db = os.path.join("/tmp", "cases.db")
        if not os.path.exists(tmp_db):
            orig_db = os.path.join(os.path.dirname(__file__), "..", "cases.db")
            if os.path.exists(orig_db):
                import shutil
                try:
                    shutil.copy2(orig_db, tmp_db)
                except Exception:
                    pass
        return tmp_db
    return os.path.join(os.path.dirname(__file__), "..", "cases.db")

DB_PATH = _get_db_path()


def _get_connection():
    db_dir = os.path.dirname(os.path.abspath(DB_PATH))
    if db_dir and not os.path.exists(db_dir):
        try:
            os.makedirs(db_dir, exist_ok=True)
        except Exception:
            pass
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables if they don't already exist. Safe to call every startup."""
    conn = _get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analyzed_at TEXT NOT NULL,
            filename TEXT,
            from_address TEXT,
            sender_domain TEXT,
            originating_ip TEXT,
            fraud_score INTEGER,
            verdict TEXT,
            full_result_json TEXT,
            evidence_hash TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER,
            action TEXT NOT NULL,
            detail TEXT,
            logged_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def create_user(username, password_hash):
    """Create a new user account. Returns True on success, False if username is taken."""
    conn = _get_connection()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, password_hash, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def get_user_by_username(username):
    """Fetch a user record by username, or None if it doesn't exist."""
    conn = _get_connection()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return dict(row) if row else None


def save_case(filename, from_address, sender_domain, originating_ip, fraud_score, verdict, full_result=None, evidence_hash=None):
    """Log a newly analyzed email as a case. Returns the new case's id."""
    conn = _get_connection()
    cursor = conn.execute(
        """
        INSERT INTO cases (analyzed_at, filename, from_address, sender_domain, originating_ip, fraud_score, verdict, full_result_json, evidence_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.now(timezone.utc).isoformat(),
            filename,
            from_address,
            sender_domain,
            originating_ip,
            fraud_score,
            verdict,
            json.dumps(full_result) if full_result else None,
            evidence_hash,
        ),
    )
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    return new_id


def get_all_cases(exclude_id=None):
    """Fetch every case (summary fields only — full_result_json excluded for speed)."""
    conn = _get_connection()
    fields = "id, analyzed_at, filename, from_address, sender_domain, originating_ip, fraud_score, verdict, evidence_hash"
    if exclude_id is not None:
        rows = conn.execute(f"SELECT {fields} FROM cases WHERE id != ? ORDER BY analyzed_at DESC", (exclude_id,)).fetchall()
    else:
        rows = conn.execute(f"SELECT {fields} FROM cases ORDER BY analyzed_at DESC").fetchall()
    conn.close()
    return [dict(row) for row in rows]


def search_cases(query):
    """Search cases by domain, IP, or filename — used by the dashboard's search box."""
    conn = _get_connection()
    like_pattern = f"%{query}%"
    fields = "id, analyzed_at, filename, from_address, sender_domain, originating_ip, fraud_score, verdict, evidence_hash"
    rows = conn.execute(
        f"""
        SELECT {fields}
        FROM cases
        WHERE sender_domain LIKE ? OR originating_ip LIKE ? OR filename LIKE ? OR from_address LIKE ?
        ORDER BY analyzed_at DESC
        """,
        (like_pattern, like_pattern, like_pattern, like_pattern),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_case(case_id):
    """Fetch ONE case including its full stored analysis result (for PDF report generation)."""
    conn = _get_connection()
    row = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    conn.close()
    if not row:
        return None

    case = dict(row)
    if case.get("full_result_json"):
        case["full_result"] = json.loads(case["full_result_json"])
    else:
        case["full_result"] = None
    return case


def log_audit_event(case_id, action, detail=""):
    """Record a chain-of-custody event."""
    conn = _get_connection()
    conn.execute(
        "INSERT INTO audit_log (case_id, action, detail, logged_at) VALUES (?, ?, ?, ?)",
        (case_id, action, detail, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    conn.close()


def get_audit_log(limit=100):
    """Fetch the most recent audit trail entries, newest first."""
    conn = _get_connection()
    rows = conn.execute(
        "SELECT * FROM audit_log ORDER BY logged_at DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


if __name__ == "__main__":
    init_db()
    print("Database initialized at:", os.path.abspath(DB_PATH))

    id1 = save_case(
        "test1.eml", "attacker@fake-bank-1.com", "fake-bank-1.com", "45.142.212.61",
        85, "Malicious", full_result={"subject": "Test invoice scam"}, evidence_hash="abc123def456"
    )
    print(f"Saved test case with id {id1}")

    log_audit_event(id1, "case_analyzed", "Initial analysis")
    log_audit_event(id1, "report_downloaded", "PDF exported")

    fetched = get_case(id1)
    print("Fetched back:", fetched["sender_domain"], "| evidence_hash:", fetched["evidence_hash"])

    audit_entries = get_audit_log()
    print(f"\nAudit log ({len(audit_entries)} entries):")
    for entry in audit_entries:
        print(f"  - case {entry['case_id']}: {entry['action']} at {entry['logged_at']} ({entry['detail']})")